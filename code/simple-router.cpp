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
    print_hdrs(packet);
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

  uint8_t *packet_ptr = packet_copy.data();
  ethernet_hdr *eth_hdr = (ethernet_hdr *)packet_ptr;

  uint8_t *mac = eth_hdr->ether_dhost;
  // check if destination hardware address is the corresponding MAC address of the interface
  bool valid = (memcmp(mac, iface->addr.data(), ETHER_ADDR_LEN) == 0);

  if (!valid)
  {
    // check if destination hardware address is a broadcast address
    valid = true;
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
      if (mac[i] != 0xFFU)
      {
        valid = false;
        break;
      }
    }
  }

  if (!valid)
  {
    // ignore Ethernet frames not destined to the router
    std::cerr << "Received packet, but the Ethernet frame isn't destined to router, ignoring" << std::endl;
    print_hdrs(packet);
    return;
  }

  uint16_t type = ntohs(eth_hdr->ether_type);
  if (type == ethertype_arp)
  {
    // handle Arp Packet
    std::cerr << "ARP packet" << std::endl;
    handleArpPacket(packet_copy, iface);
  }
  else if (type == ethertype_ip)
  {
    // handle ip Packet
    std::cerr << "IP packet" << std::endl;
    handleIpPacket(packet_copy, iface);
  }
  else
  {
    // unknown packet type
    std::cerr << "Received packet, but type is unknown, ignoring" << std::endl;
    return;
  }
}

void SimpleRouter::handleArpPacket(Buffer &packet, const Interface *inIface)
{
  print_hdrs(packet);
  ethernet_hdr *eth_header = (ethernet_hdr *)packet.data();
  arp_hdr *arp_header = (arp_hdr *)(packet.data() + sizeof(ethernet_hdr));

  // don't handle non-ethernet request or non-ipv4 request. 
  if ((ntohs(arp_header->arp_hrd) != arp_hrd_ethernet) || (ntohs(arp_header->arp_pro) != arp_pro_ip))
  {
    std::cerr << "Received packet, hrd: " << ntohs(arp_header->arp_hrd) << " , pro: " << ntohs(arp_header->arp_pro) << std::endl;
    return;
  } 

  uint16_t arpOp = ntohs(arp_header->arp_op); 

  if (arpOp == arp_op_request) { 

    // handle ARP request

    if (arp_header->arp_tip != inIface->ip)
    {
      std::cerr << "Received ARP packet, but target ip is unknown, ignoring" << std::endl;
      return;
    }

    // reply buf 
    int out_buf_size = sizeof(ethernet_hdr) + sizeof(arp_hdr); 
    uint8_t *buf = new uint8_t[out_buf_size]; 

    // the ethernet header. 
    ethernet_hdr *eth_h = (ethernet_hdr *) buf; 
    eth_h->ether_type = htons(ethertype_arp);
    memcpy(eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_h->ether_shost, inIface->addr.data(), ETHER_ADDR_LEN); 

    // the ARP header. 
    arp_hdr *arp_h = (arp_hdr *) (buf + sizeof(ethernet_hdr));
    arp_h->arp_hrd = htons(arp_hrd_ethernet);
    arp_h->arp_pro = htons(arp_pro_ip);
    arp_h->arp_hln = ETHER_ADDR_LEN;
    arp_h->arp_pln = 0x04;
    //memcpy(arp_h, arp_header, sizeof(arp_hdr));
    arp_h->arp_op = htons(arp_op_reply);
    arp_h->arp_sip = inIface->ip; 
    memcpy(arp_h->arp_sha, inIface->addr.data(), ETHER_ADDR_LEN);
    arp_h->arp_tip = arp_header->arp_sip;
    memcpy(arp_h->arp_tha, arp_header->arp_sha, ETHER_ADDR_LEN);

    // send the reply packet.
    Buffer reply(buf, buf + out_buf_size); 
    sendPacket(reply, inIface->name);
    print_hdrs(reply);
    delete[] buf;
    std::cerr << "Received ARP request packet, reply" << std::endl;
    return;
  } 
  else if (arpOp == arp_op_reply) 
  { 

    // andle ARP reply

    // reply ip.
    uint32_t sip = arp_header->arp_sip;

    Buffer smacbuf;
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
      smacbuf.push_back(arp_header->arp_sha[i]);

    // add to ARP cache
    std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(smacbuf, sip);

    // handle pending packet
    if (req != nullptr)
    {
      ethernet_hdr *eth_h;
      for (auto p : req->packets)
      {
        eth_h = (ethernet_hdr *)p.packet.data();
        memcpy(eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
        sendPacket(p.packet, p.iface);
      }
      m_arp.removeRequest(req);
    }
    std::cerr << "Received ARP reply packet, update ARP cache" << std::endl;
    return;

  } else { 
    // unknown ARP type. 
    std::cerr << "Received ARP packet, but ARP type is unknown, ignoring" << std::endl;
    return; 
  }
}

void SimpleRouter::handleIpPacket(Buffer &packet, const Interface *inIface)
{
  print_hdrs(packet);
  ethernet_hdr *eth_header = (ethernet_hdr *)packet.data();
  ip_hdr *ip_header = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));

  std::cerr << "1" << std::endl;
  // verify the minimum length
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr))
  {
    std::cerr << "Received IP packet, but packet size is too small, ignoring" << std::endl;
    return;
  }

  std::cerr << "2" << std::endl;
  // check packet checksum
  uint16_t sum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  if (cksum(ip_header, sizeof(ip_hdr)) != sum)
  {
    std::cerr << "Received IP packet, but checksum is wrong, ignoring" << std::endl;
    return;
  }

  std::cerr << "3" << std::endl;
  // uint8_t *smac = eth_header->ether_shost;

  // if (m_arp.lookup(ip_header->ip_src) == nullptr)
  // {
  //   // update ARP cache
  //   Buffer smacbuf(smac, smac + ETHER_ADDR_LEN);
  //   m_arp.insertArpEntry(smacbuf, ip_header->ip_src);
  // }
  std::cerr << "4" << std::endl;
  std::cerr << "5" << std::endl;

  if (findIfaceByIp(ip_header->ip_dst) == nullptr)
  {
    // packet is not for the router's interfaces
    //std::cerr << "packet is not for the router's interfaces" << std::endl;
    if (ip_header->ip_ttl <= 1)
    {
      // time exceeded
      sendTimeExceeded(packet, inIface);
      return;
    }

    RoutingTableEntry entry;
    try
    {
      entry = m_routingTable.lookup(ip_header->ip_dst);
    }
    catch (const std::runtime_error &e)
    {
      std::cerr << e.what() << '\n';
      std::cerr << "look up error" << std::endl;
      return;
    }

    const Interface *iface = findIfaceByName(entry.ifName);
    if (iface == nullptr)
    {
      std::cerr << "Received IP packet, but unknown interface is in routing table," 
      << entry <<"  ignoring" << std::endl;
      return;
    }

    std::cerr << "5.1" << std::endl;
    // modify the packet to forward it
    Buffer forward(packet);
    ethernet_hdr *eth_h = (ethernet_hdr *)forward.data();
    memcpy(eth_h->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

    ip_hdr *ip_h = (ip_hdr *)(forward.data() + sizeof(ethernet_hdr));
    --ip_h->ip_ttl;
    ip_h->ip_sum = 0;
    ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));

    std::shared_ptr<ArpEntry> arpentry = m_arp.lookup(ip_h->ip_dst);
    if (arpentry == nullptr)
    {
      // the target MAC address is not in ARP cache, pend the packet
      m_arp.queueRequest(ip_h->ip_dst, forward, iface->name);
      //std::cerr << "Received IP packet, packet pended" << std::endl;
      return;
    }
    else
    {
      std::cerr << "5.2.2" << std::endl;
      // the target MAC address is in ARP cache
      memcpy(eth_h->ether_dhost, arpentry->mac.data(), ETHER_ADDR_LEN);
      sendPacket(forward, iface->name);
      std::cerr << "Received IP packet, packet forwarded" << std::endl;
      return;
    }
    std::cerr << "5.3" << std::endl;
  }
  else
  {
    // packet is for the router's interfaces
    if (ip_header->ip_ttl < 1)
    {
      // time exceeded
      sendTimeExceeded(packet, inIface);
      return;
    }

    std::cerr << "packet is for the router's interfaces" << std::endl;
    if ((ip_header->ip_p == ip_protocol_tcp) || (ip_header->ip_p == ip_protocol_udp))
    {
      // an IP packet containing a UDP or TCP payload is sent to one of the router’s interfaces
      // port unreachable
      int out_buf_size = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
      uint8_t *buf = new uint8_t[out_buf_size];
      memcpy(buf, packet.data(), sizeof(ethernet_hdr) + sizeof(ip_hdr));

      // the ethernet header.
      ethernet_hdr *eth_h = (ethernet_hdr *)buf;
      memcpy(eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_h->ether_shost, eth_header->ether_dhost, ETHER_ADDR_LEN);

      // the IP header.
      ip_hdr *ip_h = (ip_hdr *)(buf+ sizeof(ethernet_hdr));
      ip_h->ip_dst = ip_header->ip_src;
      ip_h->ip_src = inIface->ip;
      ip_h->ip_p = ip_protocol_icmp;
      ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
      ip_h->ip_ttl = 64;
      ip_h->ip_sum = 0;
      ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));

      // the icmp type 3 header
      icmp_t3_hdr *icmp_t3_h = (icmp_t3_hdr *)(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      icmp_t3_h->icmp_type = icmptype_destination_unreachable;
      icmp_t3_h->icmp_code = icmpt3code_port_unreachable;
      icmp_t3_h->unused = 0;
      icmp_t3_h->next_mtu = 0;
      memcpy(icmp_t3_h->data, ip_header, ICMP_DATA_SIZE);
      icmp_t3_h->icmp_sum = 0;
      icmp_t3_h->icmp_sum = cksum(icmp_t3_h, sizeof(icmp_t3_hdr));

      // send the packet
      Buffer reply(buf, buf + out_buf_size);
      sendPacket(reply, inIface->name);
      delete[] buf;
      std::cerr << "Received IP packet, port unreachable" << std::endl;
      return;
    }
    else if (ip_header->ip_p == ip_protocol_icmp)
    {
      //
      icmp_hdr *icmp_header = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

      if (icmp_header->icmp_type == icmptype_echo)
      {
        // icmp Echo
        Buffer packet_copy(packet);
        uint8_t *packet_ptr = packet_copy.data();

        // the ethernet header.
        ethernet_hdr *eth_h = (ethernet_hdr *)packet_ptr;
        memcpy(eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_h->ether_shost, eth_header->ether_dhost, ETHER_ADDR_LEN);

        // the IP header.
        ip_hdr *ip_h = (ip_hdr *)(packet_ptr + sizeof(ethernet_hdr));
        ip_h->ip_dst = ip_header->ip_src;
        ip_h->ip_src = inIface->ip;
        ip_h->ip_p = ip_protocol_icmp;
        ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t0_hdr));
        ip_h->ip_ttl = 64;
        ip_h->ip_sum = 0;
        ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));

        icmp_t0_hdr *icmp_t0_h = (icmp_t0_hdr *)(packet_ptr + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        icmp_t0_h->icmp_type = icmptype_echo_reply;
        icmp_t0_h->icmp_code = 0;
        icmp_t0_h->icmp_sum = cksum(icmp_t0_h, sizeof(icmp_t0_hdr));

        Buffer reply(packet_ptr, packet_ptr + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t0_hdr));
        sendPacket(reply, inIface->name);
        std::cerr << "Received IP packet, echo reply" << std::endl;
        return;
      }
      else
      {
        /* code */
        std::cerr << "Received Echo packet, but type is unsupported, ignoring" << std::endl;
        return;
      }
    }
    else
    {
      std::cerr << "Received IP packet, but protocol is unsupported, ignoring" << std::endl;
      return;
    }
    
  }
  std::cerr << "6" << std::endl;
  std::cerr << "ip packet handle error" << std::endl;
}

void SimpleRouter::sendTimeExceeded(Buffer &packet, const Interface *inIface)
{
  ethernet_hdr *eth_header = (ethernet_hdr *)packet.data();
  ip_hdr *ip_header = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));

  int out_buf_size = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t11_hdr);
  uint8_t *buf = new uint8_t[out_buf_size];
  memcpy(buf, packet.data(), sizeof(ethernet_hdr) + sizeof(ip_hdr));

  // the ethernet header.
  ethernet_hdr *eth_h = (ethernet_hdr *)buf;
  memcpy(eth_h->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_h->ether_shost, eth_header->ether_dhost, ETHER_ADDR_LEN);

  // the IP header.
  ip_hdr *ip_h = (ip_hdr *)(buf + sizeof(ethernet_hdr));
  ip_h->ip_dst = ip_header->ip_src;
  ip_h->ip_src = inIface->ip;
  ip_h->ip_p = ip_protocol_icmp;
  ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t11_hdr));
  ip_h->ip_ttl = 64;
  ip_h->ip_sum = 0;
  ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));

  // the icmp type 3 header
  icmp_t11_hdr *icmp_t11_h = (icmp_t11_hdr *)(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  icmp_t11_h->icmp_type = icmptype_time_exceeded;
  icmp_t11_h->icmp_code = 0;
  icmp_t11_h->unused = 0;
  memcpy(icmp_t11_h->data, ip_header, ICMP_DATA_SIZE);
  icmp_t11_h->icmp_sum = 0;
  icmp_t11_h->icmp_sum = cksum(icmp_t11_h, sizeof(icmp_t11_hdr));

  // send the packet
  Buffer reply(buf, buf + out_buf_size);
  sendPacket(reply, inIface->name);
  delete[] buf;
  std::cerr << "Received ip packet, time exceeded" << std::endl;
  return;
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
