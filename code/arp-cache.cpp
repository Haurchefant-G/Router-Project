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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
uint8_t mac_broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  std::lock_guard<std::mutex> lock(m_mutex);

  int out_buf_size = sizeof(ethernet_hdr) + sizeof(arp_hdr);
  uint8_t *buf = new uint8_t[out_buf_size];

  ethernet_hdr *eth_h = (ethernet_hdr *)buf;
  eth_h->ether_type = htons(ethertype_arp);
  memcpy(eth_h->ether_dhost, mac_broadcast, ETHER_ADDR_LEN);
  //memcpy(eth_h->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

  // copy in the ARP header information.
  arp_hdr *arp_h = (arp_hdr *)(buf + sizeof(ethernet_hdr));
  arp_h->arp_hrd = htons(arp_hrd_ethernet);
  arp_h->arp_pro = htons(arp_pro_ip);
  arp_h->arp_hln = htons(ETHER_ADDR_LEN);
  arp_h->arp_pln = htons(0x04);

  //memcpy(arp_h, arp_header, sizeof(arp_hdr)); // copy in all fields
  arp_h->arp_op = htons(arp_op_request);
  //arp_h->arp_sip = iface->ip;
  //memcpy(arp_h->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
  //arp_h->arp_tip = request->ip;
  memcpy(arp_h->arp_tha, mac_broadcast, ETHER_ADDR_LEN);

  // send the packet
  // Buffer arp_request(buf, buf + out_buf_size);
  // m_router.sendPacket(arp_request, iface->name);

  // FILL THIS IN
  for (auto it = m_arpRequests.begin(); it != m_arpRequests.end(); )
  {
    auto request = *it;
    if (request->nTimesSent >= MAX_SENT_TIME)
    {
      // host unreachable

      it = m_arpRequests.erase(it);
    } 
    else 
    {
      const Interface *iface = m_router.findIfaceByName(request->packets.front().iface);

      // int out_buf_size = sizeof(ethernet_hdr) + sizeof(arp_hdr);
      // uint8_t *buf = new uint8_t[out_buf_size];

      // // copy in the ethernet header fields.
      // ethernet_hdr *eth_h = (ethernet_hdr *)buf;
      // eth_h->ether_type = htons(ethertype_arp);
      // memcpy(eth_h->ether_dhost, mac_broadcast, ETHER_ADDR_LEN);
      memcpy(eth_h->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

      // copy in the ARP header information.
      // arp_hdr *arp_h = (arp_hdr *)(buf + sizeof(ethernet_hdr));
      // arp_h->arp_hrd = htons(arp_hrd_ethernet);
      // arp_h->arp_pro = htons(arp_pro_ip);
      // arp_h->arp_hln = htons(ETHER_ADDR_LEN);
      // arp_h->arp_pln = htons(0x04);

      //memcpy(arp_h, arp_header, sizeof(arp_hdr)); // copy in all fields
      // arp_h->arp_op = htons(arp_op_request);
      arp_h->arp_sip = iface->ip;
      memcpy(arp_h->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      arp_h->arp_tip = request->ip;
      // memcpy(arp_h->arp_tha, mac_broadcast, ETHER_ADDR_LEN);

      // send the packet
      Buffer arp_request(buf, buf + out_buf_size);
      m_router.sendPacket(arp_request, iface->name);
      // delete[] buf;

      ++request->nTimesSent;
      request->timeSent = steady_clock::now();
      ++it;
    }
  }
  delete[] buf;

  for (auto it = m_cacheEntries.begin(); it != m_cacheEntries.end();)
  {
    auto entry = *it;
    if (!entry->isValid)
    {
      it = m_cacheEntries.erase(it);
    }
    else
    {
      ++it;
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
