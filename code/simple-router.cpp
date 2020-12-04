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

  void *packet_ptr = packet.data();
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

  if (ntohs(eth_hdr->ether_type) == ethertype_arp)
  {
    handle_arp_packet(packet_ptr + sizeof(ethernet_hdr), iface, eth_hdr->ether_shost);
  }
  else if (ntohs(eth_hdr->ether_type) == ethertype_ip)
  {
    handle_ip_packet(packet, iface, eth_hdr->ether_shost);
  }
  else
  {
    std::cerr << "Received packet, but type is unknown, ignoring" << std::endl;
    return;
  }
}

void SimpleRouter::handleArpPacket(uint8_t* data, const Interface* inIface, uint8_t* smac)
{
  arp_hdr* arp_header = (arp_hdr *) data; 

  // don't handle non-ethernet requests. 
  if (ntohs(arp_header->arp_hrd) != arp_hrd_ethernet || ntohs(arp_header->arp_pro) != arp_pro_ip) 
     return; 

  uint16_t arp_op_type = ntohs(arp_header->arp_op); 

  if (arp_op_type == arp_op_request) { 

    /* Handle ARP requests */

    // if the arp request isn't for the router, we can exit. 
    if (arp_header->arp_tip != inIface->ip)
       return; 

    // prepare an output buffer for the response. 
    int out_buf_size = sizeof(ethernet_hdr) + sizeof(arp_hdr); 
    uint8_t buf[out_buf_size]; 

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
    return; 

  } 
  else if (arp_op_type == arp_op_reply) 
  { 

    /* Handle ARP replies */

    // extract information from the ARP header.
    uint32_t sip = arp_header->arp_sip;

    Buffer smac;
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
      smac.push_back(arp_header->arp_sha[i]);

    std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(smac, sip);

    if (req != nullptr)
    {
      ethernet_hdr *eth_h;
      for (auto packet : req->packets)
      {
        eth_h = (ethernet_hdr *)packet.packet.data();
        memcpy(eth_h->ether_dhost, smac.data(), ETHER_ADDR_LEN);
        sendPacket(packet.packet, packet.iface);
      }

      m_arp.removeRequest(req);
    }
    return;
    
  } else { 
    // don't handle undocumented ARP packet types. 
    fprintf(stderr, "Received ARP packet, but ARP type is unknown, "
        "ignoring\n");
    std::cerr << "Received ARP packet, but ARP type is unknown, ignoring" << std::endl;
    return; 
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
