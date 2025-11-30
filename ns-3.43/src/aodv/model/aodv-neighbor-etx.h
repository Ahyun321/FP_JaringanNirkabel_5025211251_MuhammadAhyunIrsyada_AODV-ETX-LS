/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
 
#ifndef AODVNEIGHBORETX_H
#define AODVNEIGHBORETX_H

#include <map>
#include "ns3/ipv4-address.h"
#include "ns3/aodv-packet.h"
#include "ns3/vector.h" // <--- WAJIB: Untuk menyimpan posisi/kecepatan

namespace ns3
{
namespace aodv
{

class NeighborEtx
{
public:
  NeighborEtx ();
  
  struct Etx
  {
    uint16_t m_lppMyCnt10bMap;
    uint8_t m_lppReverse;
    
    // --- TAMBAHAN UNTUK LET ---
    Vector m_position; 
    Vector m_velocity; 
    // ---------------------------

    Etx () : m_lppMyCnt10bMap (0), m_lppReverse (0), m_position(0,0,0), m_velocity(0,0,0) {}
  };
   
  uint8_t GetLppTimeStamp () {return m_lppTimeStamp; }
  void GotoNextTimeStampAndClearOldest ();
  void FillLppCntData (LppHeader &lppHeader);
  
  // --- FUNGSI UPDATE BARU (Dengan Vector) ---
  bool UpdateNeighborEtx (Ipv4Address addr, uint8_t lppTimeStamp, uint8_t lppReverse, Vector neighborPos, Vector neighborVel);
  
  uint32_t GetEtxForNeighbor (Ipv4Address addr);

  // --- FUNGSI METRIK HYBRID (ETX + LET) ---
  uint32_t GetHybridMetric (Ipv4Address addr, Vector myPos, Vector myVel);

  static uint32_t EtxMaxValue () { return UINT32_MAX; };

private:
  std::map<Ipv4Address, Etx> m_neighborEtx;
  uint8_t m_lppTimeStamp; 
   
  uint32_t CalculateBinaryShiftedEtx (struct Etx etxStruct);
  
  // --- HITUNG LET ---
  double CalculateLet (Vector myPos, Vector myVel, Vector neighPos, Vector neighVel);

  uint8_t Lpp10bMapToCnt (uint16_t lpp10bMap);
  void GotoNextLppTimeStamp ();
  static uint8_t CalculateNextLppTimeStamp (uint8_t currTimeStamp);
};

} // namespace aodv
} // namespace ns3

#endif /* AODVNEIGHBORETX_H */