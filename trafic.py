import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import datetime


class TrainingStats(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(TrainingStats, self).__init__(*args, **kwargs)
        self.paths = {}
        self.monitor_thread = hub.spawn(self.monitor)

        file0 = open("Model.csv", "w")
        file0.write(
            'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration,flow_duration_ns,timeout,hard_timeout,flags,packet_count,byte_count,count_packets,count_packets_ns,count_byte,count_byte_ns,label\n')
        file0.close()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.paths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.paths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.paths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.paths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.paths.values():
                self.request(dp)
            hub.sleep(10)

    def request(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def handler_flow(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        file0 = open("Model.csv", "a+")
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
                count_packets = stat.packet_count / stat.duration
                count_packets_ns = stat.packet_count / stat.duration_ns
            except:
                count_packets = 0
                count_packets_ns = 0

            try:
                count_byte = stat.byte_count / stat.duration
                count_byte_ns = stat.byte_count / stat.duration_ns
            except:
                count_byte = 0
                count_byte_ns = 0

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                stat.match['ip_proto'], icmp_code, icmp_type,
                                stat.duration, stat.duration_ns,
                                stat.timeout, stat.hard_timeout,
                                stat.flags, stat.packet_count, stat.byte_count,
                                count_packets, count_packets_ns,
                                count_byte, count_byte_ns, 0))
        file0.close()


# reaction_module.py
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score


class Monitor13(switchm.Switch13):

    def __init__(self, *args, **kwargs):

        super(Monitor13, self).__init__(*args, **kwargs)
        self.paths = {}
        self.thread_mon = hub.spawn(self._monitor)

        start = datetime.now()

        self.training_flow()

        end = datetime.now()
        print("Training time: ", (end - start))

    @set_ev_cls(ofp_event.EventOFPieChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _ie_change_handler(self, ev):
        datapath = ev.datapath
        if ev.ie == MAIN_DISPATCHER:
            if datapath.id not in self.paths:
                self.logg.debug('register datapath: %016x', datapath.id)
                self.paths[datapath.id] = datapath
        elif ev.ie == DEAD_DISPATCHER:
            if datapath.id in self.paths:
                self.logg.debug('unregister datapath: %016x', datapath.id)
                del self.paths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.paths.values():
                self.requests(dp)
            hub.sleep(10)

            self.flow_predict()

    def requests(self, datapath):
        self.logg.debug('send is request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowisRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowisReply, MAIN_DISPATCHER)
    def _flow_is_reply_handler(self, ev):

        time_temp = datetime.now()
        time_temp = time_temp.time_temp()

        file0 = open("PredictModel.csv", "w")
        file0.write(
            'time_temp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,count_packets,count_packets_ns,count_byte,count_byte_ns\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for i in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
        (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = i.match['ipv4_src']
            ip_dst = i.match['ipv4_dst']
            ip_proto = i.match['ip_proto']

            if i.match['ip_proto'] == 1:
                icmp_code = i.match['icmpv4_code']
                icmp_type = i.match['icmpv4_type']

            elif i.match['ip_proto'] == 6:
                tp_src = i.match['tcp_src']
                tp_dst = i.match['tcp_dst']

            elif i.match['ip_proto'] == 17:
                tp_src = i.match['udp_src']
                tp_dst = i.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                count_packets = i.packet_count / i.duration_sec
                count_packets_ns = i.packet_count / i.duration_nsec
            except:
                count_packets = 0
                count_packets_ns = 0

            try:
                count_byte = i.byte_count / i.duration_sec
                count_byte_ns = i.byte_count / i.duration_nsec
            except:
                count_byte = 0
                count_byte_ns = 0

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(time_temp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                i.match['ip_proto'], icmp_code, icmp_type,
                                i.duration_sec, i.duration_nsec,
                                i.idle_timeout, i.hard_timeout,
                                i.flags, i.packet_count, i.byte_count,
                                count_packets, count_packets_ns,
                                count_byte, count_byte_ns))

        file0.close()

    def training_flow(self):

        self.logg.info("Flow Training ...")

        flow_dataset = pd.read_csv('Flowisfile.csv')

        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

        X_flow = flow_dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')

        y_flow = flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25,
                                                                                random_ie=0)

        classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_ie=0)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictModel.csv')

            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')

            y_flow_pred = self.flow_model.predict(X_predict_flow)

            normal_trafic = 0
            ddos_trafic = 0

            for i in y_flow_pred:
                if i == 0:
                    normal_trafic += 1
                else:
                    ddos_trafic += 1
                    victim = int(predict_flow_dataset.iloc[i, 5]) % 20

            self.logg.info("...")
            if (normal_trafic / len(y_flow_pred) * 100) > 80:
                self.logg.info("Traffic is Normal")
            else:
                self.logg.info("DoS Attack in Progress!!!")
                self.logg.info("Victim Host: h{}".format(victim))
                print("Mitigation process in progress!")
                self.mitigation = 1

            self.logg.info("...")

            file0 = open("PredictModel.csv", "w")

            file0.write(
                'time_temp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,count_packets,count_packets_ns,count_byte,count_byte_ns\n')
            file0.close()

        except:
            pass
