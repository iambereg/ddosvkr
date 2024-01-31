from ryu.controller import event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switch

import datetime


class TrainingCollect(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(TrainingCollect, self).__init__(*args, **kwargs)
        self.paths = {}
        self.monitor_chase = hub.spawn(self.monitor_chase)

    @set_ev_cls(event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.paths:
                self.logg.debug('register datapath: %016x', datapath.id)
                self.paths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.paths:
                self.logg.debug('unregister datapath: %016x', datapath.id)
                del self.paths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.paths.values():
                self.requests(dp)
            hub.sleep(10)

    def requests(self, datapath):
        self.logg.debug('send stats request: %016x', datapath.id)

        parser_data = datapath.ofproto_parser_data

        req = parser_data.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        file0 = open("FlowStatsfile.csv", "a+")

        body = ev.msg.body
        for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
        (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']

            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']

            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                count_packets = stat.packet_count / stat.duration_sec
                count_packets_ns = stat.packet_count / stat.duration_nsec
            except:
                count_packets = 0
                count_packets_ns = 0

            try:
                count_byte = stat.byte_count / stat.duration_sec
                count_byte_ns = stat.byte_count / stat.duration_nsec
            except:
                count_byte = 0
                count_byte_ns = 0

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                stat.match['ip_proto'], icmp_code, icmp_type,
                                stat.duration_sec, stat.duration_nsec,
                                stat.idle_timeout, stat.hard_timeout,
                                stat.flags, stat.packet_count, stat.byte_count,
                                count_packets, count_packets_ns,
                                count_byte, count_byte_ns, 1))
        file0.close()
