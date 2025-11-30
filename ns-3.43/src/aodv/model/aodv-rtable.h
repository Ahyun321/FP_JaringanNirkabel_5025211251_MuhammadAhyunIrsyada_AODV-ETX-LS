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
 *
 * Based on
 * NS-2 AODV model developed by the CMU/MONARCH group and optimized and
 * tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 *
 * AODV-UU implementation by Erik Nordström of Uppsala University
 * http://core.it.uu.se/core/index.php/AODV-UU
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 * Pavel Boyko <boyko@iitp.ru>
 */
#ifndef AODV_RTABLE_H
#define AODV_RTABLE_H

#include <stdint.h>
#include <cassert>
#include <map>
#include <vector>
#include <sys/types.h>
#include "ns3/ipv4.h"
#include "ns3/ipv4-route.h"
#include "ns3/timer.h"
#include "ns3/net-device.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/simulator.h"

namespace ns3 {
namespace aodv {

/**
 * \ingroup aodv
 * \brief Route record states
 */
enum RouteFlags
{
  VALID = 0,          //!< VALID
  INVALID = 1,        //!< INVALID
  IN_SEARCH = 2,      //!< IN_SEARCH
};

/**
 * \ingroup aodv
 * \brief Routing table entry
 */
class RoutingTableEntry
{
public:
  /**
   * constructor
   *
   * \param dev the device
   * \param dst the destination IP address
   * \param vSeqNo verify sequence number flag
   * \param seqNo the sequence number
   * \param iface the interface
   * \param hops the number of hops
   * \param nextHop the IP address of the next hop
   * \param lifetime the lifetime of the entry
   * \param etx the ETX/LET metric (Updated)
   */
  // --- PERBAIKAN: Default parameter disesuaikan dan ditambahkan etx ---
  RoutingTableEntry (Ptr<NetDevice> dev = 0, Ipv4Address dst = Ipv4Address (), bool vSeqNo = false, uint32_t seqNo = 0,
                     Ipv4InterfaceAddress iface = Ipv4InterfaceAddress (), uint16_t  hops = 0,
                     Ipv4Address nextHop = Ipv4Address (), Time lifetime = Simulator::GetMaximumSimulationTime (), 
                     uint32_t etx = 0);

  ~RoutingTableEntry ();

  ///\name Precursors management
  //\{
  bool InsertPrecursor (Ipv4Address id);
  bool LookupPrecursor (Ipv4Address id);
  bool DeletePrecursor (Ipv4Address id);
  void DeleteAllPrecursors ();
  bool IsPrecursorListEmpty () const;
  void GetPrecursors (std::vector<Ipv4Address> & prec) const;
  //\}

  void Invalidate (Time badLinkLifetime);

  // Fields
  Ipv4Address GetDestination () const { return m_ipv4Route->GetDestination (); }
  Ptr<Ipv4Route> GetRoute () const { return m_ipv4Route; }
  void SetRoute (Ptr<Ipv4Route> r) { m_ipv4Route = r; }
  void SetNextHop (Ipv4Address nextHop) { m_ipv4Route->SetGateway (nextHop); }
  Ipv4Address GetNextHop () const { return m_ipv4Route->GetGateway (); }
  void SetOutputDevice (Ptr<NetDevice> dev) { m_ipv4Route->SetOutputDevice (dev); }
  Ptr<NetDevice> GetOutputDevice () const { return m_ipv4Route->GetOutputDevice (); }
  Ipv4InterfaceAddress GetInterface () const { return m_iface; }
  void SetInterface (Ipv4InterfaceAddress iface) { m_iface = iface; }
  void SetValidSeqNo (bool s) { m_validSeqNo = s; }
  bool GetValidSeqNo () const { return m_validSeqNo; }
  void SetSeqNo (uint32_t sn) { m_seqNo = sn; }
  uint32_t GetSeqNo () const { return m_seqNo; }
  void SetHop (uint16_t hop) { m_hops = hop; }
  uint16_t GetHop () const { return m_hops; }
  void SetLifeTime (Time lt) { m_lifeTime = lt + Simulator::Now (); }
  Time GetLifeTime () const { return m_lifeTime - Simulator::Now (); }
  void SetFlag (RouteFlags flag) { m_flag = flag; }
  RouteFlags GetFlag () const { return m_flag; }
  void SetRreqCnt (uint8_t n) { m_reqCount = n; }
  uint8_t GetRreqCnt () const { return m_reqCount; }
  void IncrementRreqCnt () { m_reqCount++; }
  void SetUnidirectional (bool u) { m_blackListState = u; }
  bool IsUnidirectional () const { return m_blackListState; }
  void SetBlacklistTimeout (Time t) { m_blackListTimeout = t; }
  Time GetBlacklistTimeout () const { return m_blackListTimeout; }

  // --- PERBAIKAN: Menggunakan nama m_etx agar konsisten dengan file .cc ---
  uint32_t GetEtx () const { return m_etx; }
  void SetEtx (uint32_t etx) { m_etx = etx; }
  // -----------------------------------------------------------------------

  /// RREP_ACK timer
  Timer m_ackTimer;

  bool operator== (Ipv4Address const  dst) const
  {
    return (m_ipv4Route->GetDestination () == dst);
  }
  
  void Print (Ptr<OutputStreamWrapper> stream) const;

private:
  bool m_validSeqNo;
  uint32_t m_seqNo;
  uint16_t m_hops;
  Time m_lifeTime;
  Ptr<Ipv4Route> m_ipv4Route;
  Ipv4InterfaceAddress m_iface;
  RouteFlags m_flag;
  std::vector<Ipv4Address> m_precursorList;
  Time m_routeRequestTimout;
  uint8_t m_reqCount;
  bool m_blackListState;
  Time m_blackListTimeout;
  
  // --- PERBAIKAN: Variabel diganti dari m_etx10000 menjadi m_etx ---
  uint32_t m_etx;
};

/**
 * \ingroup aodv
 * \brief The Routing table used by AODV protocol
 */
class RoutingTable
{
public:
  RoutingTable (Time t);
  ///\name Handle lifetime of invalid route
  //\{
  Time GetBadLinkLifetime () const { return m_badLinkLifetime; }
  void SetBadLinkLifetime (Time t) { m_badLinkLifetime = t; }
  //\}
  bool AddRoute (RoutingTableEntry & r);
  bool DeleteRoute (Ipv4Address dst);
  bool LookupRoute (Ipv4Address dst, RoutingTableEntry & rt);
  bool LookupValidRoute (Ipv4Address dst, RoutingTableEntry & rt);
  bool Update (RoutingTableEntry & rt);
  bool SetEntryState (Ipv4Address dst, RouteFlags state);
  void GetListOfDestinationWithNextHop (Ipv4Address nextHop, std::map<Ipv4Address, uint32_t> & unreachable);
  void InvalidateRoutesWithDst (std::map<Ipv4Address, uint32_t> const & unreachable);
  void DeleteAllRoutesFromInterface (Ipv4InterfaceAddress iface);
  void Clear () { m_ipv4AddressEntry.clear (); }
  void Purge ();
  bool MarkLinkAsUnidirectional (Ipv4Address neighbor, Time blacklistTimeout);
  void Print (Ptr<OutputStreamWrapper> stream) const;

private:
  std::map<Ipv4Address, RoutingTableEntry> m_ipv4AddressEntry;
  Time m_badLinkLifetime;
  void Purge (std::map<Ipv4Address, RoutingTableEntry> &table) const;
};

}  // namespace aodv
}  // namespace ns3

#endif /* AODV_RTABLE_H */