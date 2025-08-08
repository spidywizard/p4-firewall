/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
 
/* CONSTANTS */
 
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<8>  TYPE_ICMP = 1;
 
#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1
#define RATE_METER_ENTRIES 4096
#define RATE_THRESHOLD 336
#define FLOWLET_TIMEOUT 48w100000  // 100ms in microseconds
 
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
 
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
 
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
 
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
 
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
 
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
 
header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}
 
struct metadata {
    bit<32> register_position_one;
    bit<32> register_position_two;
    bit<1>  register_cell_one;
    bit<1>  register_cell_two;
 
    // Rate meter metadata
    bit<32> rate_index;       // Index for rate limiting registers
    bit<32> packet_count;     // Counter for packets
    bit<48> current_time;     // Current timestamp
    bit<48> last_time;        // Last seen timestamp
    bit<32> time_diff;        // Time difference
    bit<1>  is_rate_limited;  // Flag to indicate if traffic is rate limited
    bit<1>  is_h3h4_to_h1h2;  // Flag to identify traffic from h3/h4 to h1/h2
}
 
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
    icmp_t     icmp;
}
 
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
 
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
 
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: ipv4;
            default: accept;
        }
    }
 
    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            TYPE_ICMP: icmp;
            default: accept;
        }
    }
 
    state tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
 
    state udp {
        packet.extract(hdr.udp);
        transition accept;
    }
 
    state icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}
 
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
 
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}
 
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
 
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
 
    // Original firewall registers
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter;
 
    // New registers for rate limiting
    register<bit<32>>(RATE_METER_ENTRIES) packet_counter;
    register<bit<48>>(RATE_METER_ENTRIES) last_seen;
 
    action drop() {
        mark_to_drop(standard_metadata);
    }
 
    // Firewall actions
    action set_allowed() {
        //Get register position
        hash(meta.register_position_one, HashAlgorithm.crc16, (bit<32>)0, 
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol},
            (bit<32>)BLOOM_FILTER_ENTRIES);
 
        hash(meta.register_position_two, HashAlgorithm.crc32, (bit<32>)0, 
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol},
            (bit<32>)BLOOM_FILTER_ENTRIES);
 
        //set bloom filter fields
        bloom_filter.write(meta.register_position_one, 1);
        bloom_filter.write(meta.register_position_two, 1);
    }
 
    action check_if_allowed() {
        //Get register position
        hash(meta.register_position_one, HashAlgorithm.crc16, (bit<32>)0, 
            {hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.ipv4.protocol},
            (bit<32>)BLOOM_FILTER_ENTRIES);
 
        hash(meta.register_position_two, HashAlgorithm.crc32, (bit<32>)0, 
            {hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.ipv4.protocol},
            (bit<32>)BLOOM_FILTER_ENTRIES);
 
        //Read bloom filter cells to check if there are 1's
        bloom_filter.read(meta.register_cell_one, meta.register_position_one);
        bloom_filter.read(meta.register_cell_two, meta.register_position_two);
    }
 
    // Rate meter actions
    action check_rate() {
        // Get current timestamp
        meta.current_time = standard_metadata.ingress_global_timestamp;
 
        // Calculate index for the rate meter based on source and destination IPs
        hash(meta.rate_index, HashAlgorithm.crc32, (bit<32>)0, 
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 
            (bit<32>)RATE_METER_ENTRIES);
 
        // Read last timestamp and packet count
        last_seen.read(meta.last_time, meta.rate_index);
        packet_counter.read(meta.packet_count, meta.rate_index);
 
        // Calculate time difference
        meta.time_diff = (bit<32>)(meta.current_time - meta.last_time);
 
        // If time difference > 1s (1,000,000 microseconds), reset counter
        if (meta.time_diff > 1000000 || meta.last_time == 0) {
            meta.packet_count = 1;
            meta.is_rate_limited = 0;
        }
        else {
            // Increment packet counter
            meta.packet_count = meta.packet_count + 1;
 
            // Check if rate exceeds threshold
            if (meta.packet_count > RATE_THRESHOLD) {
                meta.is_rate_limited = 1;
            } else {
                meta.is_rate_limited = 0;
            }
        }
 
        // Update registers
        packet_counter.write(meta.rate_index, meta.packet_count);
        last_seen.write(meta.rate_index, meta.current_time);
    }
 
    action identify_h3h4_to_h1h2() {
        // Identify traffic from h3/h4 (10.0.3.0/24, 10.0.4.0/24) to h1/h2 (10.0.1.0/24, 10.0.2.0/24)
        bit<8> src_subnet = hdr.ipv4.srcAddr[31:24];
        bit<8> dst_subnet = hdr.ipv4.dstAddr[31:24];
 
        // Check if source is from h3/h4 subnet and destination is h1/h2 subnet
        if ((src_subnet == 10 && hdr.ipv4.srcAddr[23:16] == 0 && 
             (hdr.ipv4.srcAddr[15:8] == 3 || hdr.ipv4.srcAddr[15:8] == 4)) &&
            (dst_subnet == 10 && hdr.ipv4.dstAddr[23:16] == 0 && 
             (hdr.ipv4.dstAddr[15:8] == 1 || hdr.ipv4.dstAddr[15:8] == 2))) {
            meta.is_h3h4_to_h1h2 = 1;
        } else {
            meta.is_h3h4_to_h1h2 = 0;
        }
    }
 
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        //set the src mac address as the previous dst
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
 
        //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;
 
        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;
 
        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
 
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
 
    apply {
        if (hdr.ipv4.isValid()) {
            // Check if this is switch s1 (based on standard_metadata.ingress_port values)
            if (standard_metadata.ingress_port == 1 || standard_metadata.ingress_port == 2) {
                // Identify if traffic is from h3/h4 to h1/h2
                identify_h3h4_to_h1h2();
 
                // If traffic is from h3/h4 to h1/h2, apply rate limiting
                if (meta.is_h3h4_to_h1h2 == 1) {
                    check_rate();
 
                    // Drop packet if rate limit exceeded
                    if (meta.is_rate_limited == 1) {
                        drop();
                        return;
                    }
                }
            }
 
            // Continue with normal firewall processing for TCP traffic
            if (hdr.tcp.isValid()) {
                // Packet comes from internal network
                if (standard_metadata.ingress_port == 1) {
                    //If there is a syn we update the bloom filter and add the entry
                    if (hdr.tcp.syn == 1) {
                        set_allowed();
                    }
                }
                // Packet comes from outside
                else if (standard_metadata.ingress_port == 2) {
                    check_if_allowed();
 
                    // we let the flow pass
                    if (meta.register_cell_one != 1 || meta.register_cell_two != 1) {
                        drop();
                        return;
                    }
                }
            }
 
            // Apply IP forwarding
            ipv4_lpm.apply();
        }
    }
}
 
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
 
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}
 
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
 
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}
 
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
 
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}
 
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
 
//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
