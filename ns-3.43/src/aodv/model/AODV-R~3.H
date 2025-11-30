/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 * ... (License Text) ...
 */
#ifndef AODVROUTINGPROTOCOL_H
#define AODVROUTINGPROTOCOL_H

#include "aodv-rtable.h"
#include "aodv-rqueue.h"
#include "aodv-packet.h"
#include "aodv-neighbor.h"
#include "aodv-dpd.h"
#include "ns3/node.h"
#include "ns3/random-variable-stream.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/ipv4-l3-protocol.h"
#include <map>
#include "aodv-neighbor-etx.h"
#include "ns3/traced-callback.h"

namespace ns3 {
namespace aodv {
/**
 * \ingroup aodv
 *
 * \brief AODV routing protocol
 */
class RoutingProtocol : public Ipv4RoutingProtocol
{
public:
  static TypeId GetTypeId (void);
  static const uint32_t AODV_PORT;

  /// constructor
  RoutingProtocol ();
  virtual ~RoutingProtocol ();
  virtual void DoDispose ();

  // Inherited from Ipv4RoutingProtocol
  Ptr<Ipv4Route> RouteOutput (Ptr<Packet> p, const Ipv4Header &header, Ptr<NetDevice> oif, Socket::SocketErrno &sockerr);
  
  // --- PERBAIKAN: Signature disesuaikan dengan NS-3.43 (menggunakan const &) ---
  virtual bool RouteInput (Ptr<const Packet> p, const Ipv4Header &header, Ptr<const NetDevice> idev,
                           const UnicastForwardCallback &ucb, const MulticastForwardCallback &mcb,
                           const LocalDeliverCallback &lcb, const ErrorCallback &ecb);
  // -----------------------------------------------------------------------------

  virtual void NotifyInterfaceUp (uint32_t interface);
  virtual void NotifyInterfaceDown (uint32_t interface);
  virtual void NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address);
  virtual void NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address);
  virtual void SetIpv4 (Ptr<Ipv4> ipv4);
  virtual void PrintRoutingTable (Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const;

  // Handle protocol parameters
  Time GetMaxQueueTime () const { return m_maxQueueTime; }
  void SetMaxQueueTime (Time t);
  uint32_t GetMaxQueueLen () const { return m_maxQueueLen; }
  void SetMaxQueueLen (uint32_t len);
  bool GetDestinationOnlyFlag () const { return m_destinationOnly; }
  void SetDestinationOnlyFlag (bool f) { m_destinationOnly = f; }
  bool GetGratuitousReplyFlag () const { return m_gratuitousReply; }
  void SetGratuitousReplyFlag (bool f) { m_gratuitousReply = f; }
  void SetHelloEnable (bool f) { m_enableHello = f; }
  bool GetHelloEnable () const { return m_enableHello; }
  void SetBroadcastEnable (bool f) { m_enableBroadcast = f; }
  bool GetBroadcastEnable () const { return m_enableBroadcast; }
  void SetEtxEnable (bool f) { m_enableEtx = f; }
  bool GetEtxEnable () const { return m_enableEtx; }

  int64_t AssignStreams (int64_t stream);

protected:
  virtual void DoInitialize (void);
private:
  // Protocol parameters.
  uint32_t m_rreqRetries;             
  uint16_t m_ttlStart;                
  uint16_t m_ttlIncrement;            
  uint16_t m_ttlThreshold;            
  uint16_t m_timeoutBuffer;           
  uint16_t m_rreqRateLimit;           
  uint16_t m_rerrRateLimit;           
  Time m_activeRouteTimeout;          
  uint32_t m_netDiameter;             
  Time m_nodeTraversalTime;
  Time m_netTraversalTime;             
  Time m_pathDiscoveryTime;            
  Time m_myRouteTimeout;               
  Time m_helloInterval;
  uint32_t m_allowedHelloLoss;         
  Time m_deletePeriod;
  Time m_nextHopWait;                  
  Time m_blackListTimeout;             
  uint32_t m_maxQueueLen;              
  Time m_maxQueueTime;                 
  bool m_destinationOnly;              
  bool m_gratuitousReply;              
  bool m_enableHello;                  
  bool m_enableBroadcast;              

  /// IP protocol
  Ptr<Ipv4> m_ipv4;
  std::map< Ptr<Socket>, Ipv4InterfaceAddress > m_socketAddresses;
  std::map< Ptr<Socket>, Ipv4InterfaceAddress > m_socketSubnetBroadcastAddresses;
  Ptr<NetDevice> m_lo;

  /// Routing table
  RoutingTable m_routingTable;
  /// A "drop-front" queue used by the routing layer to buffer packets.
  RequestQueue m_queue;
  uint32_t m_requestId;
  uint32_t m_seqNo;
  IdCache m_rreqIdCache;
  DuplicatePacketDetection m_dpd;
  Neighbors m_nb;
  uint16_t m_rreqCount;
  uint16_t m_rerrCount;

  /// ETX for neighbors
  NeighborEtx m_nbEtx;
   
private:
  void Start ();
  void DeferredRouteOutput (Ptr<const Packet> p, const Ipv4Header & header, UnicastForwardCallback ucb, ErrorCallback ecb);
  bool Forwarding (Ptr<const Packet> p, const Ipv4Header & header, UnicastForwardCallback ucb, ErrorCallback ecb);
  void ScheduleRreqRetry (Ipv4Address dst);
  bool UpdateRouteLifeTime (Ipv4Address addr, Time lt);
  void UpdateRouteToNeighbor (Ipv4Address sender, Ipv4Address receiver);
  bool IsMyOwnAddress (Ipv4Address src);
  Ptr<Socket> FindSocketWithInterfaceAddress (Ipv4InterfaceAddress iface) const;
  Ptr<Socket> FindSubnetBroadcastSocketWithInterfaceAddress (Ipv4InterfaceAddress iface) const;
  void ProcessHello (RrepHeader const & rrepHeader, Ipv4Address receiverIfaceAddr);
  Ptr<Ipv4Route> LoopbackRoute (const Ipv4Header & header, Ptr<NetDevice> oif) const;

  /// Receive control packets
  void RecvAodv (Ptr<Socket> socket);
  void RecvRequest (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src);
  void RecvReply (Ptr<Packet> p, Ipv4Address my,Ipv4Address src);
  void RecvReplyAck (Ipv4Address neighbor);
  void RecvError (Ptr<Packet> p, Ipv4Address src);
  void RecvLpp (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src);

  /// Send
  void SendPacketFromQueue (Ipv4Address dst, Ptr<Ipv4Route> route);
  void SendHello ();
  void SendLpp ();
  void SendRequest (Ipv4Address dst);
  void SendReply (RreqHeader const & rreqHeader, RoutingTableEntry const & toOrigin);
  void SendReplyByIntermediateNode (RoutingTableEntry & toDst, RoutingTableEntry & toOrigin, bool gratRep);
  void SendReplyAck (Ipv4Address neighbor);
  void SendRerrWhenBreaksLinkToNextHop (Ipv4Address nextHop);
  void SendRerrMessage (Ptr<Packet> packet,  std::vector<Ipv4Address> precursors);
  void SendRerrWhenNoRouteToForward (Ipv4Address dst, uint32_t dstSeqNo, Ipv4Address origin);
  void SendTo (Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination);

  /// Enable link probe packets for ETX metric
  bool m_enableEtx;
  Time m_lppInterval;
  Timer m_lppTimer;
  void LppTimerExpire ();

  Timer m_htimer;
  void HelloTimerExpire ();
  Timer m_rreqRateLimitTimer;
  void RreqRateLimitTimerExpire ();
  Timer m_rerrRateLimitTimer;
  void RerrRateLimitTimerExpire ();
  std::map<Ipv4Address, Timer> m_addressReqTimer;
  void RouteRequestTimerExpire (Ipv4Address dst);
  void AckTimerExpire (Ipv4Address neighbor, Time blacklistTimeout);

  Ptr<UniformRandomVariable> m_uniformRandomVariable;
  Time m_lastBcastTime;
  TracedCallback<Ptr<const Packet> > m_txTrace; 
};

} //namespace aodv
} //namespace ns3

#endif /* AODVROUTINGPROTOCOL_H */