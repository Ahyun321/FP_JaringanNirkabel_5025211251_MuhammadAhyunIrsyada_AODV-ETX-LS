/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 University of Belgrade, Faculty of Traffic and Transport Engineering
 * ... (License Text) ...
 */
#ifndef AODVPACKET_H
#define AODVPACKET_H

#include <iostream>
#include "ns3/header.h"
#include "ns3/enum.h"
#include "ns3/ipv4-address.h"
#include <map>
#include "ns3/nstime.h"
#include "ns3/vector.h" // <--- TAMBAHAN 1: Wajib untuk Vector (Posisi/Kecepatan)

namespace ns3 {
namespace aodv {

/**
* \ingroup aodv
* \brief MessageType enumeration
*/
enum MessageType
{
  AODVTYPE_RREQ  = 1,   //!< AODVTYPE_RREQ
  AODVTYPE_RREP  = 2,   //!< AODVTYPE_RREP
  AODVTYPE_RERR  = 3,   //!< AODVTYPE_RERR
  AODVTYPE_RREP_ACK = 4, //!< AODVTYPE_RREP_ACK
  AODVTYPE_LPP = 5      //!< AODVTYPE_LPP
};

/**
* \ingroup aodv
* \brief AODV types
*/
class TypeHeader : public Header
{
public:
  TypeHeader (MessageType t = AODVTYPE_RREQ);
  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const;
  uint32_t GetSerializedSize () const;
  void Serialize (Buffer::Iterator start) const;
  uint32_t Deserialize (Buffer::Iterator start);
  void Print (std::ostream &os) const;
  MessageType Get () const { return m_type; }
  bool IsValid () const { return m_valid; }
  bool operator== (TypeHeader const & o) const;
private:
  MessageType m_type; 
  bool m_valid; 
};

std::ostream & operator<< (std::ostream & os, TypeHeader const & h);

/**
* \ingroup aodv
* \brief Route Request (RREQ) Message Format
*/
class RreqHeader : public Header
{
public:
   // Constructor dimodifikasi untuk menerima Position dan Velocity (default 0)
   RreqHeader (uint8_t flags = 0, uint8_t reserved = 0, uint8_t hopCount = 0,
              uint32_t requestID = 0, Ipv4Address dst = Ipv4Address (),
              uint32_t dstSeqNo = 0, Ipv4Address origin = Ipv4Address (),
              uint32_t originSeqNo = 0, uint32_t etxMetric = 0,
              Vector pos = Vector(0,0,0), Vector vel = Vector(0,0,0));

  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const;
  uint32_t GetSerializedSize () const;
  void Serialize (Buffer::Iterator start) const;
  uint32_t Deserialize (Buffer::Iterator start);
  void Print (std::ostream &os) const;

  // Fields
  void SetHopCount (uint8_t count) { m_hopCount = count; }
  uint8_t GetHopCount () const { return m_hopCount; }
  void SetId (uint32_t id) { m_requestID = id; }
  uint32_t GetId () const { return m_requestID; }
  void SetDst (Ipv4Address a) { m_dst = a; }
  Ipv4Address GetDst () const { return m_dst; }
  void SetDstSeqno (uint32_t s) { m_dstSeqNo = s; }
  uint32_t GetDstSeqno () const { return m_dstSeqNo; }
  void SetOrigin (Ipv4Address a) { m_origin = a; }
  Ipv4Address GetOrigin () const { return m_origin; }
  void SetOriginSeqno (uint32_t s) { m_originSeqNo = s; }
  uint32_t GetOriginSeqno () const { return m_originSeqNo; }
  void SetEtx (uint32_t s) { m_etxMetric = s; }
  uint32_t GetEtx () const { return m_etxMetric; }

  // --- TAMBAHAN UNTUK LET (RREQ) ---
  void SetPosition (Vector p) { m_position = p; }
  Vector GetPosition () const { return m_position; }
  void SetVelocity (Vector v) { m_velocity = v; }
  Vector GetVelocity () const { return m_velocity; }
  // ---------------------------------

  // Flags
  void SetGratuitousRrep (bool f);
  bool GetGratuitousRrep () const;
  void SetDestinationOnly (bool f);
  bool GetDestinationOnly () const;
  void SetUnknownSeqno (bool f);
  bool GetUnknownSeqno () const;

  bool operator== (RreqHeader const & o) const;
private:
  uint8_t        m_flags;          
  uint8_t        m_reserved;       
  uint8_t        m_hopCount;       
  uint32_t       m_requestID;      
  Ipv4Address    m_dst;            
  uint32_t       m_dstSeqNo;       
  Ipv4Address    m_origin;          
  uint32_t       m_originSeqNo;    
  uint32_t       m_etxMetric;       
  
  // --- DATA BARU ---
  Vector         m_position; // Posisi Pengirim
  Vector         m_velocity; // Kecepatan Pengirim
};

std::ostream & operator<< (std::ostream & os, RreqHeader const &);

/**
* \ingroup aodv
* \brief Route Reply (RREP) Message Format
*/
class RrepHeader : public Header
{
public:
  // Constructor dimodifikasi
  RrepHeader (uint8_t prefixSize = 0, uint8_t hopCount = 0, Ipv4Address dst =
                Ipv4Address (), uint32_t dstSeqNo = 0, Ipv4Address origin =
                Ipv4Address (), Time lifetime = MilliSeconds (0), uint32_t etxMetric = 0,
                Vector pos = Vector(0,0,0), Vector vel = Vector(0,0,0));

  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const;
  uint32_t GetSerializedSize () const;
  void Serialize (Buffer::Iterator start) const;
  uint32_t Deserialize (Buffer::Iterator start);
  void Print (std::ostream &os) const;

  // Fields
  void SetHopCount (uint8_t count) { m_hopCount = count; }
  uint8_t GetHopCount () const { return m_hopCount; }
  void SetDst (Ipv4Address a) { m_dst = a; }
  Ipv4Address GetDst () const { return m_dst; }
  void SetDstSeqno (uint32_t s) { m_dstSeqNo = s; }
  uint32_t GetDstSeqno () const { return m_dstSeqNo; }
  void SetOrigin (Ipv4Address a) { m_origin = a; }
  Ipv4Address GetOrigin () const { return m_origin; }
  void SetLifeTime (Time t);
  Time GetLifeTime () const;
  void SetEtx (uint32_t s) { m_etxMetric = s; }
  uint32_t GetEtx () const { return m_etxMetric; }

  // --- TAMBAHAN UNTUK LET (RREP) ---
  void SetPosition (Vector p) { m_position = p; }
  Vector GetPosition () const { return m_position; }
  void SetVelocity (Vector v) { m_velocity = v; }
  Vector GetVelocity () const { return m_velocity; }
  // ---------------------------------

  // Flags
  void SetAckRequired (bool f);
  bool GetAckRequired () const;
  void SetPrefixSize (uint8_t sz);
  uint8_t GetPrefixSize () const;

  void SetHello (Ipv4Address src, uint32_t srcSeqNo, Time lifetime);
  bool operator== (RrepHeader const & o) const;
private:
  uint8_t        m_flags;                  
  uint8_t        m_prefixSize;         
  uint8_t             m_hopCount;          
  Ipv4Address    m_dst;               
  uint32_t       m_dstSeqNo;          
  Ipv4Address      m_origin;            
  uint32_t       m_lifeTime;          
  uint32_t       m_etxMetric;         
  
  // --- DATA BARU ---
  Vector         m_position;
  Vector         m_velocity;
};

std::ostream & operator<< (std::ostream & os, RrepHeader const &);

/**
* \ingroup aodv
* \brief Route Reply Acknowledgement (RREP-ACK) Message Format
*/
class RrepAckHeader : public Header
{
public:
  RrepAckHeader ();
  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const;
  uint32_t GetSerializedSize () const;
  void Serialize (Buffer::Iterator start) const;
  uint32_t Deserialize (Buffer::Iterator start);
  void Print (std::ostream &os) const;
  bool operator== (RrepAckHeader const & o) const;
private:
  uint8_t       m_reserved; 
};

std::ostream & operator<< (std::ostream & os, RrepAckHeader const &);

/**
* \ingroup aodv
* \brief Route Error (RERR) Message Format
*/
class RerrHeader : public Header
{
public:
  RerrHeader ();
  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const;
  uint32_t GetSerializedSize () const;
  void Serialize (Buffer::Iterator i) const;
  uint32_t Deserialize (Buffer::Iterator start);
  void Print (std::ostream &os) const;

  void SetNoDelete (bool f);
  bool GetNoDelete () const;
  bool AddUnDestination (Ipv4Address dst, uint32_t seqNo);
  bool RemoveUnDestination (std::pair<Ipv4Address, uint32_t> & un);
  void Clear ();
  uint8_t GetDestCount () const { return (uint8_t)m_unreachableDstSeqNo.size (); }
  bool operator== (RerrHeader const & o) const;
private:
  uint8_t m_flag;            
  uint8_t m_reserved;        
  std::map<Ipv4Address, uint32_t> m_unreachableDstSeqNo;
};

std::ostream & operator<< (std::ostream & os, RerrHeader const &);

/**
* \ingroup aodv
* \brief  Link probe packet (LPP) Message Format
*/
class LppHeader : public Header 
{
public:
  // Constructor
  LppHeader (Vector pos = Vector(0,0,0), Vector vel = Vector(0,0,0));

  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const;
  uint32_t GetSerializedSize () const;
  void Serialize (Buffer::Iterator start) const;
  uint32_t Deserialize (Buffer::Iterator start);
  void Print (std::ostream &os) const;

  // Fields
  void SetLppId (uint8_t count) { m_lppId = count; }
  uint8_t GetLppId () const { return m_lppId; }
  void SetOriginAddress (Ipv4Address a) { m_originAddr = a; }
  Ipv4Address GetOriginAddress () const { return m_originAddr; }
  void SetOriginSeqno (uint32_t seqno) { m_originSeqno = seqno; }
  uint32_t GetOriginSeqno () const { return m_originSeqno; }
  uint16_t GetNumberNeighbors () const { return (uint8_t)m_neighborsLppCnt.size (); }

  // --- TAMBAHAN UNTUK LET (LPP) ---
  void SetPosition (Vector p) { m_position = p; }
  Vector GetPosition () const { return m_position; }
  void SetVelocity (Vector v) { m_velocity = v; }
  Vector GetVelocity () const { return m_velocity; }
  // --------------------------------

  bool AddToNeighborsList (Ipv4Address neighbor, uint8_t lppCnt);
  bool RemoveFromNeighborsList (std::pair<Ipv4Address, uint8_t> & un);
  void ClearNeighborsList ();
  bool operator== (LppHeader const & o) const;

private:
  uint8_t       m_lppId;          
  Ipv4Address    m_originAddr;     
  uint32_t      m_originSeqno;    

  // --- DATA BARU ---
  Vector        m_position;
  Vector        m_velocity;

  std::map<Ipv4Address, uint8_t> m_neighborsLppCnt;
};

std::ostream & operator<< (std::ostream & os, LppHeader const &);

}  // namespace aodv
}  // namespace ns3

#endif /* AODVPACKET_H */
