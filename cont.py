from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switch

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import matrix_c
from sklearn.metrics import accuracy_score


class SimpleMonitor13(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):

        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.data = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()

        self.flow_training()

        end = datetime.now()
        print("Training time: ", (end - start))

    @set_ev_cls(ofp_event.EventOFPseChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _se_change_handler(self, ev):
        datap = ev.datap
        if ev.se == MAIN_DISPATCHER:
            if datap.id not in self.data:
                self.logger.debug('register datap: %016x', datap.id)
                self.data[datap.id] = datap
        elif ev.se == DEAD_DISPATCHER:
            if datap.id in self.data:
                self.logger.debug('unregister datap: %016x', datap.id)
                del self.data[datap.id]

    def _monitor(self):
        while True:
            for dp in self.data.values():
                self._request_ss(dp)
            hub.sleep(10)

            self.f_predict()

    def _request_ss(self, datap):
        self.logger.debug('send ss request: %016x', datap.id)
        parser = datap.ofproto_parser

        req = parser.OFPFlowssRequest(datap)
        datap.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowssReply, MAIN_DISPATCHER)
    def _flow_ss_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()

        file = open("predictss.csv", "w")
        file.write(
            'timestamp,datap_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,pers,pers_n,byt_s,byte_ns\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for s in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
        (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = s.match['ipv4_src']
            ip_dst = s.match['ipv4_dst']
            ip_proto = s.match['ip_proto']

            if s.match['ip_proto'] == 1:
                icmp_code = s.match['icmpv4_code']
                icmp_type = s.match['icmpv4_type']

            elif s.match['ip_proto'] == 6:
                tp_src = s.match['tcp_src']
                tp_dst = s.match['tcp_dst']

            elif s.match['ip_proto'] == 17:
                tp_src = s.match['udp_src']
                tp_dst = s.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                pers = s.packet_count / s.duration_sec
                pers_n = s.packet_count / s.duration_nsec
            except:
                pers = 0
                pers_n = 0

            try:
                byt_s = s.byte_count / s.duration_sec
                byte_ns = s.byte_count / s.duration_nsec
            except:
                byt_s = 0
                byte_ns = 0

            file.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                       .format(timestamp, ev.msg.datap.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                               s.match['ip_proto'], icmp_code, icmp_type,
                               s.duration_sec, s.duration_nsec,
                               s.idle_timeout, s.hard_timeout,
                               s.flags, s.packet_count, s.byte_count,
                               pers, pers_n,
                               byt_s, byte_ns))

        file.close()

    def flow_training(self):

        self.logger.info("Flow Training ...")

        ds = pd.read_csv('Flowssfile.csv')

        ds.iloc[:, 2] = ds.iloc[:, 2].str.replace('.', '')
        ds.iloc[:, 3] = ds.iloc[:, 3].str.replace('.', '')
        ds.iloc[:, 5] = ds.iloc[:, 5].str.replace('.', '')

        X_flow = ds.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')

        y_flow = ds.iloc[:, -1].values

        X_t_f, X_t, y_t, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_se=0)

        classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_se=0)
        self.model = classifier.fit(X_t_f, y_t)

        y_flow_pred = self.model.predict(X_t)

        self.logger.info("------------------------------------------------------------------------------")

        self.logger.info("confusion matrix")
        cm = matrix_c(y_flow_test, y_flow_pred)
        self.logger.info(cm)

        acc = accuracy_score(y_flow_test, y_flow_pred)

        self.logger.info("succes accuracy = {0:.2f} %".format(acc * 100))
        fail = 1.0 - acc
        self.logger.info("fail accuracy = {0:.2f} %".format(fail * 100))
        self.logger.info("------------------------------------------------------------------------------")

    def f_predict(self):
        try:
            predict_ds = pd.read_csv('predictss.csv')

            predict_ds.iloc[:, 2] = predict_ds.iloc[:, 2].str.replace('.', '')
            predict_ds.iloc[:, 3] = predict_ds.iloc[:, 3].str.replace('.', '')
            predict_ds.iloc[:, 5] = predict_ds.iloc[:, 5].str.replace('.', '')

            X_predict_flow = predict_ds.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')

            y_flow_pred = self.model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0

            for i in y_flow_pred:
                if i == 0:
                    legitimate_trafic = legitimate_trafic + 1
                else:
                    ddos_trafic = ddos_trafic + 1
                    victim = int(predict_ds.iloc[i, 5]) % 20

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_trafic / len(y_flow_pred) * 100) > 80:
                self.logger.info("legitimate trafic ...")
            else:
                self.logger.info("ddos trafic ...")
                self.logger.info("victim is host: h{}".format(victim))

            self.logger.info("------------------------------------------------------------------------------")

            file = open("predictss.csv", "w")

            file.write(
                'timestamp,datap_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,pers,pers_n,byt_s,byte_ns\n')
            file.close()

        except:
            pass