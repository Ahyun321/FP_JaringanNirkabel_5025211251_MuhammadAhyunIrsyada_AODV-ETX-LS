/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 * ... (License header tetap sama) ...
 */
 
#include "aodv-neighbor-etx.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include <math.h>
#include <stdint.h>

namespace ns3
{
  
NS_LOG_COMPONENT_DEFINE ("AodvNeighborEtx");

namespace aodv
{

NeighborEtx::NeighborEtx () : m_lppTimeStamp (0) {}

uint8_t
NeighborEtx::CalculateNextLppTimeStamp (uint8_t currTimeStamp)
{
  uint8_t nextTimeStamp = currTimeStamp + 1;
  if (nextTimeStamp > 11)
    {
      nextTimeStamp = 0;
    }
  return nextTimeStamp;
}

void
NeighborEtx::GotoNextLppTimeStamp ()
{
  m_lppTimeStamp = CalculateNextLppTimeStamp (m_lppTimeStamp);
}

uint8_t 
NeighborEtx::Lpp10bMapToCnt (uint16_t lpp10bMap)
{
  uint8_t lpp = 0;
  for (int j=0; j<12; ++j)
    {
      if ((j!=m_lppTimeStamp) && (j!=(m_lppTimeStamp+1)))
        {
          lpp += (lpp10bMap & ((uint16_t)0x0001 << j)) ? 1 : 0;
        }
    }
  return lpp;
}

void
NeighborEtx::GotoNextTimeStampAndClearOldest ()
{
  GotoNextLppTimeStamp (); 
  for (std::map<Ipv4Address, Etx>::iterator i = m_neighborEtx.begin (); i != m_neighborEtx.end (); ++i)
    {
      Etx etx = i->second;
      uint16_t lppMyCnt10bMap = etx.m_lppMyCnt10bMap;
      lppMyCnt10bMap &= (uint16_t)(~((uint16_t)0x0001 << CalculateNextLppTimeStamp (m_lppTimeStamp)) & (uint16_t)0x0FFF);
      etx.m_lppMyCnt10bMap = lppMyCnt10bMap;
      i->second = etx;
    }  
}

void
NeighborEtx::FillLppCntData (LppHeader &lppHeader)
{
  for (std::map<Ipv4Address, Etx>::iterator i = m_neighborEtx.begin (); i != m_neighborEtx.end (); ++i)
        {
          uint8_t lpp = Lpp10bMapToCnt (i->second.m_lppMyCnt10bMap);
          if (lpp > 0)
            {
              lppHeader.AddToNeighborsList (i->first, lpp);
            }
        }
}

// --- IMPLEMENTASI BARU: UPDATE DENGAN POSISI & KECEPATAN ---
bool 
NeighborEtx::UpdateNeighborEtx (Ipv4Address addr, uint8_t lppTimeStamp, uint8_t lppReverse, Vector neighborPos, Vector neighborVel)
{
  std::map<Ipv4Address, Etx>::iterator i = m_neighborEtx.find (addr);
  if (i == m_neighborEtx.end ())
    {
      Etx etx;
      etx.m_lppReverse = lppReverse;
      etx.m_lppMyCnt10bMap = (uint16_t)0x0001 << lppTimeStamp;
      
      // Simpan data mobilitas tetangga
      etx.m_position = neighborPos;
      etx.m_velocity = neighborVel;
      
      m_neighborEtx.insert (std::make_pair (addr, etx));
      return true;
    }
  else
    {
      i->second.m_lppReverse = lppReverse;
      (i->second.m_lppMyCnt10bMap) |= ((uint16_t)0x0001 << lppTimeStamp);
      
      // Update data mobilitas tetangga
      i->second.m_position = neighborPos;
      i->second.m_velocity = neighborVel;
      return true;
    }
}

uint32_t 
NeighborEtx::CalculateBinaryShiftedEtx (Etx etxStruct)
{
  uint32_t etx = UINT32_MAX;
  if ((Lpp10bMapToCnt (etxStruct.m_lppMyCnt10bMap)!=0) && (etxStruct.m_lppReverse!=0))
    {
      etx = (uint32_t) (round (1000000.0 / (Lpp10bMapToCnt (etxStruct.m_lppMyCnt10bMap) * etxStruct.m_lppReverse)));
    }
  return etx;
}

uint32_t 
NeighborEtx::GetEtxForNeighbor (Ipv4Address addr)
{
  std::map<Ipv4Address, Etx>::iterator i = m_neighborEtx.find (addr);
  if (i == m_neighborEtx.end ())
    {
      return UINT32_MAX;
    }
  else
    {
      return CalculateBinaryShiftedEtx (i->second);
    }
}

// --- IMPLEMENTASI BARU: HITUNG LET ---
double 
NeighborEtx::CalculateLet (Vector myPos, Vector myVel, Vector neighPos, Vector neighVel)
{
  double r = 250.0; // Jangkauan Transmisi WiFi (default 250m)
  
  double a = myVel.x - neighVel.x;
  double b = myPos.x - neighPos.x;
  double c = myVel.y - neighVel.y;
  double d = myPos.y - neighPos.y;

  double denominator = (a * a) + (c * c);
  if (denominator == 0) return 1000.0; // Bergerak relatif sama/diam

  double term1 = -( (a * b) + (c * d) );
  double termUnderSqrt = ( (a*a + c*c) * (r*r) ) - ( (a*d - b*c) * (a*d - b*c) );

  if (termUnderSqrt < 0) return 0.0; // Sudah diluar jangkauan

  double let = (term1 + sqrt(termUnderSqrt)) / denominator;
  return (let < 0) ? 0.0 : let;
}

// --- IMPLEMENTASI BARU: HITUNG METRIK GABUNGAN ---
uint32_t 
NeighborEtx::GetHybridMetric (Ipv4Address addr, Vector myPos, Vector myVel)
{
  std::map<Ipv4Address, Etx>::iterator i = m_neighborEtx.find (addr);
  if (i == m_neighborEtx.end ()) return UINT32_MAX;

  // 1. Hitung ETX
  uint32_t baseEtx = CalculateBinaryShiftedEtx (i->second);

  // 2. Hitung LET
  double let = CalculateLet (myPos, myVel, i->second.m_position, i->second.m_velocity);

  // NS_LOG_UNCOND ("IP: " << addr << " ETX: " << baseEtx << " LET: " << let);

  // 3. Logika Threshold: Jika LET < 1 detik, anggap link putus (Max Metric)
  if (let < 1.0) 
    {
      return UINT32_MAX; 
    }
  
  return baseEtx;
}

} // namespace aodv
} // namespace ns3