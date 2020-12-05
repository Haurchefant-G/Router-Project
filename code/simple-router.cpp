/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  if (packet.size() < sizeof(ethernet_hdr))
  {
    std::cerr << "Received packet, but packet size is too small, ignoring" << std::endl;
    return;
  }

  /* Parse the ethernet header */

  Buffer packet_copy(packet);

  void *packet_ptr = packet_copy.data();
  ethernet_hdr *eth_hdr = (ethernet_hdr *)packet_ptr;

  uint8_t *mac = eth_hdr->ether_dhost;
  bool valid = true;
  for (int i = 0; i < ETHER_ADDR_LEN; i++)
  {
    if (mac[i] != 0xFFU)
    {
      valid = false;
      break;
    }
  }

  if (!valid)
  {
    valid = (memcmp(mac, iface->addr.data(), ETHER_ADDR_LEN) == 0);
  }

  if (!valid)
  {
    std::cerr << "Received packet, but the Ethernet frame isn't destined to router, ignoring" << std::endl;
    return;
  }

  /* Handle the ethernet packet based on its type */

  uint16_t type = ntohs(eth_hdr->ether_type);
  if (type == ethertype_arp)
  {
    //handle_arp_packet(packet_ptr + sizeof(ethernet_hdr), iface, eth_hdr->ether_shost);
    handleArpPacket(packet_copy, iface);
  }
  else if (type == ethertype_ip)
  {
    handleIpPacket(packet_copy, iface);
    //handle_ip_packet(packet_copy, iface, eth_hdr->ether_shost);
  }
  else
  {
    std::cerr << "Received packet, but type is unknown, ignoring" << std::endl;
    return;
  }
}

void SimpleRouter::handleArpPacket(Buffer &packet, const Interface *inIface)
{
  ethernet_hdr *eth_header = (eth_header *)packet.data();
  arp_hdr *arp_header = (arp_hdr *)(packet.data() + sizeof(ethernet_hdr));

  uint8_t *smac = eth_header->ether_shost;

  // don't handle non-ethernet requests. 
  if (ntohs(arp_header->arp_hrd) != arp_hrd_ethernet || ntohs(arp_header->arp_pro) != arp_pro_ip) 
     return; 

  uint16_t arpOp = ntohs(arp_header->arp_op); 

  if (arpOp == arp_op_request) { 

    /* Handle ARP requests */

    // if the arp request isn't for the router, we can exit. 
    if (arp_header->arp_tip != inIface->ip)
       return; 

    // prepare an output buffer for the response. 
    int out_buf_size = sizeof(ethernet_hdr) + sizeof(arp_hdr); 
    uint8_t *buf = new uint8_t[out_buf_size]; 

    // copy in the ethernet header fields. 
    ethernet_hdr *eth_h = (ethernet_hdr *) buf; 
    eth_h->ether_type = htons(ethertype_arp); 
    memcpy(eth_h->ether_dhost, smac, ETHER_ADDR_LEN); 
    memcpy(eth_h->ether_shost, inIface->addr.data(), ETHER_ADDR_LEN); 

    // copy in the ARP header information. 
    arp_hdr *arp_h = (arp_hdr *) (buf + sizeof(ethernet_hdr));
    arp_h->arp_hrd = htons(arp_hrd_fmt);
    arp_h->arp_pro = htons(arp_pro_fmt);
    arp_h->arp_hln = htons(ETHER_ADDR_LEN);
    arp_h->arp_pln = htons(0x04);

    //memcpy(arp_h, arp_header, sizeof(arp_hdr)); // copy in all fields
    arp_h->arp_op = htons(arp_op_reply);
    arp_h->arp_sip = inIface->ip; 
    memcpy(arp_h->arp_sha, inIface->addr.data(), ETHER_ADDR_LEN);
    arp_h->arp_tip = arp_header->arp_sip;
    memcpy(arp_h->arp_tha, arp_header->arp_sha, ETHER_ADDR_LEN);

    // send the packet
    Buffer reply(buf, buf + out_buf_size); 
    sendPacket(reply, inIface->name);
    delete[] buf;
    return;
  } 
  else if (arpOp == arp_op_reply) 
  { 

    /* Handle ARP replies */

    // extract information from the ARP header.
    uint32_t sip = arp_header->arp_sip;

    Buffer smacbuf;
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
      smacbuf.push_back(arp_header->arp_sha[i]);

    std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(smacbuf, sip);

    if (req != nullptr)
    {
      ethernet_hdr *eth_h;
      for (auto p : req->packets)
      {
        eth_h = (ethernet_hdr *)p.packet.data();
        memcpy(eth_h->ether_dhost, smac, ETHER_ADDR_LEN);
        sendPacket(p.packet, p.iface);
      }

      m_arp.removeRequest(req);
    }
    return;

  } else { 
    // don't handle undocumented ARP packet types. 
    std::cerr << "Received ARP packet, but ARP type is unknown, ignoring" << std::endl;
    return; 
  }
}

void SimpleRouter::handleIpPacket(Buffer &packet, const Interface *inIface)
{
  ethernet_hdr *eth_header = (eth_header *)packet.data();
  ip_hdr *ip_header = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));

  if (packet.size < sizeof(ethernet_hdr) + sizeof(ip_hdr))
  {
    std::cerr << "Received IP packet, but packet size is too small, ignoring" << std::endl;
    return;
  }


  // check packet checksum
  uint16_t checksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  if (cksum(ip_header, sizeof(ip_hdr)) != ip_header->ip_sum)
  {
    std::cerr << "Received IP packet, but checksum is wrong, ignoring" << std::endl;
    return;
  }

  uint8_t *smac = eth_header->ether_shost;

  if (m_arp.lookup(ip_header->ip_src) == nullptr)
  {
    Buffer smacbuf(smac, smac + ETHER_ADDR_LEN);
    m_arp.insertArpEntry(smacbuf, ip_header->ip_src);
  }

  if (ip_header->ip_ttl <= 1)
  {

  }

  if (findIfaceByIp(ip_header->ip_dst) == nullptr)
  {
    RoutingTableEntry entry;
    try
    {
      m_routingTable.lookup(ip_header->ip_dst);
    }
    catch (const std::runtime_error &e)
    {
      std::cerr << e.what() << '\n';
      return;
    }

    const Interface *iface = findIfaceByName(entry.ifName);
    if (iface == nullptr)
    {
      std::cerr << "Received IP packet, but unknown interface is in routing table, ignoring" << std::endl;
      return;
    }

    Buffer forward(packet);
    ethernet_hdr *eth_h = (eth_header *)forward.data();
    ip_hdr *ip_h = (ip_hdr *)(forward.data() + sizeof(ethernet_hdr));

    memcpy(eth_h->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
    --ip_h->ip_ttl;
    ip_h->ip_sum = 0;
    ip_h->ip_sum = checksum(ip_h, sizeof(ip_hdr));

    std::shared_ptr<ArpEntry> arpentry = m_arp.lookup(ip_h->ip_dst);
    if (arpentry == nullptr)
    {
      m_arp.queueRequest(ip_h->ip_dst, forward, iface);
      return;
    }
    else
    {
      memcpy(eth_h->ether_dhost, arpentry->mac.data(), ETHER_ADDR_LEN);
      sendPacket(forward, iface->name);
      return;
    }
  }
  else
  {
    
    if (ip_header->ip_p != ip_protocol_icmp)
    {
      //
      int out_buf_size = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
      uint8_t *buf = new uint8_t[out_buf_size];

      memcpy(buf, packet.data(), sizeof(ethernet_hdr) + sizeof(ip_hdr));

      // copy in the ethernet header fields.
      ethernet_hdr *eth_h = (ethernet_hdr *)buf;
      memcpy(eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_h->ether_shost, eth_header->ether_dhost, ETHER_ADDR_LEN);

      ip_hdr *ip_h = (ip_hdr *)(packet_ptr + sizeof(ethernet_hdr));
      ip_h->ip_dst = ip_header->ip_src;
      ip_h->ip_src = ip_header->ip_dst;
      ip_h->ip_p = ip_protocol_icmp;
      ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
      ip_h->ip_ttl = 256;
      ip_h->ip_sum = 0;
      ip_h->ip_sum = checksum(ip_h, sizeof(ip_hdr));

      icmp_t3_hdr *icmp_t3_h = (icmp_t3_hdr *)(packet_ptr + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      icmp_t3_h->icmp_type = icmptype_destination_unreachable;
      icmp_t3_h->icmp_code = icmpt3code_port_unreachable;
      icmp_t3_h->unused = 0;
      icmp_t3_h->next_mtu = 0;
      memcpy(icmp_t3_h->data, ip_header, ICMP_DATA_SIZE);
      icmp_h->icmp_sum = 0;
      icmp_h->icmp_sum = cksum(icmp_h, sizeof(icmp_hdr));
      // send the packet
      Buffer reply(buf, buf + out_buf_size);
      sendPacket(reply, inIface->name);
      delete[] buf;
      return
    }
    icmp_hdr *icmp_header = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

    if (icmp_header->icmp_type == icmptype_echo)
    {
      Buffer packet_copy(packet);
      void *packet_ptr = packet_copy.data();

      ethernet_hdr *eth_h = (ethernet_hdr *)packet_ptr;
      memcpy(eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_h->ether_shost, eth_header->ether_dhost, ETHER_ADDR_LEN);

      ip_hdr *ip_h = (ip_hdr *)(packet_ptr + sizeof(ethernet_hdr));
      ip_h->ip_dst = ip_header->ip_src;
      ip_h->ip_src = ip_header->ip_dst;
      ip_h->ip_ttl = 256;
      ip_h->ip_sum = 0;
      ip_h->ip_sum = checksum(ip_h, sizeof(ip_hdr));

      icmp_hdr *icmp_h = (icmp_hdr *)(packet_ptr + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      icmp_h->icmp_type = icmptype_echo_reply;
      icmp_h->icmp_code = 0;
      icmp_h->icmp_sum = cksum(icmp_h, sizeof(icmp_hdr));

      Buffer reply(packet_ptr, packet_ptr + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));
      sendPacket(reply, inIface->name);
      return;
    }
    else
    {
      /* code */
    }
    
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
