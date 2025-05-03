import os
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import threading
import time
import joblib
import json
import logging
import numpy as np
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
import requests
from concurrent.futures import ThreadPoolExecutor


class TrafficClassifierService(win32serviceutil.ServiceFramework):
    _svc_name_ = "TrafficClassifierService"
    _svc_display_name_ = "Traffic Classifier Background Service"
    _svc_description_ = "Captures network traffic, classifies it using ML, and logs results."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

        this_dir = os.path.dirname(os.path.abspath(__file__))

        config_path = os.path.join(this_dir, 'config.json')
        with open(config_path, 'r') as f:
            config = json.load(f)

        self.MY_DEVICE_IP = config['MY_DEVICE_IP']
        self.MODEL_PATH = os.path.join(this_dir, config['MODEL_PATH'])
        self.LABEL_ENCODER_PATH = os.path.join(this_dir, config['LABEL_ENCODER_PATH'])
        self.CAPTURE_INTERFACE = config['CAPTURE_INTERFACE']
        self.CAPTURE_TIME = config['CAPTURE_TIME']
        self.LOG_FILE = os.path.join(this_dir, config['LOG_FILE'])
        self.API_ENDPOINT = config['API_ENDPOINT']

        logging.basicConfig(filename=self.LOG_FILE, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        self.model = joblib.load(self.MODEL_PATH)
        self.label_encoder = joblib.load(self.LABEL_ENCODER_PATH)
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)
        logging.info("Traffic Classifier Service stopping...")
        self.post_log_to_server("INFO", f"{self.MY_DEVICE_IP} - Service stopping...")

    def SvcDoRun(self):
        logging.info("Traffic Classifier Service starting...")
        self.post_log_to_server("INFO", f"{self.MY_DEVICE_IP} - Service starting...")
        self.main()

    def post_log_to_server(self, level, message):
        try:
            payload = {"level": level, "message": message}
            log_endpoint = self.API_ENDPOINT.replace("/predict", "/logs")
            requests.post(log_endpoint, json=payload, timeout=3)
        except Exception as e:
            logging.error(f"❌ Failed to send log to server: {str(e)}")

    def packet_filter(self, pkt):
        if not pkt.haslayer(IP):
            return False
        if pkt.haslayer(ARP):
            return False
        if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            return False
        ip_layer = pkt.getlayer(IP)
        if ip_layer.src != self.MY_DEVICE_IP and ip_layer.dst != self.MY_DEVICE_IP:
            return False
        return True

    def capture_packets(self):
        logging.info(f"Capturing traffic on {self.CAPTURE_INTERFACE} for {self.CAPTURE_TIME} seconds...")
        packets = sniff(iface=self.CAPTURE_INTERFACE, timeout=self.CAPTURE_TIME, lfilter=self.packet_filter)
        logging.info(f"Captured {len(packets)} packets (filtered).")
        return packets

    def extract_features(self, packets):
        if len(packets) == 0:
            return None

        times = [pkt.time for pkt in packets]
        sizes = [len(pkt) for pkt in packets]
        src_ports, dst_ports, src_ips, dst_ips = [], [], [], []

        for pkt in packets:
            if pkt.haslayer(IP):
                ip_layer = pkt.getlayer(IP)
                src_ips.append(ip_layer.src)
                dst_ips.append(ip_layer.dst)
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                src_ports.append(pkt.sport)
                dst_ports.append(pkt.dport)

        iats = np.diff(times) if len(times) > 1 else np.array([0])

        feature_dict = {
            'Flow.Duration': (times[-1] - times[0]) if len(times) > 1 else 0,
            'Total.Fwd.Packets': len(packets),
            'Total.Length.of.Fwd.Packets': np.sum(sizes),
            'Fwd.Packet.Length.Max': np.max(sizes) if sizes else 0,
            'Fwd.Packet.Length.Min': np.min(sizes) if sizes else 0,
            'Fwd.Packet.Length.Mean': np.mean(sizes) if sizes else 0,
            'Fwd.Packet.Length.Std': np.std(sizes) if sizes else 0,
            'Flow.Bytes.s': np.sum(sizes) / (times[-1] - times[0] + 1e-6),
            'Flow.Packets.s': len(packets) / (times[-1] - times[0] + 1e-6),
            'Flow.IAT.Mean': np.mean(iats),
            'Flow.IAT.Std': np.std(iats),
            'Flow.IAT.Max': np.max(iats),
            'Flow.IAT.Min': np.min(iats),
            'Min.Packet.Length': np.min(sizes) if sizes else 0,
            'Max.Packet.Length': np.max(sizes) if sizes else 0,
            'Packet.Length.Mean': np.mean(sizes) if sizes else 0,
            'Packet.Length.Std': np.std(sizes) if sizes else 0,
            'Packet.Length.Variance': np.var(sizes) if sizes else 0,
            'Average.Packet.Size': np.mean(sizes) if sizes else 0,
            'num_unique_dst_ips': len(set(dst_ips)),
            'num_unique_dst_ports': len(set(dst_ports)),
        }

        self.last_src_ip = next((ip for ip in src_ips if ip != self.MY_DEVICE_IP), "Unknown")
        self.last_dst_ip = next((ip for ip in dst_ips if ip != self.MY_DEVICE_IP), "Unknown")

        model_features = self.model.feature_names_in_
        full_features = {feat: feature_dict.get(feat, 0.0) for feat in model_features}

        return pd.DataFrame([full_features])

    def send_prediction(self, payload):
        try:
            response = requests.post(self.API_ENDPOINT, json=payload, timeout=5)
            if response.status_code in (200, 201):
                msg = f"{self.MY_DEVICE_IP} - ✅ Prediction POST successful!"
                logging.info(msg)
                self.post_log_to_server("INFO", msg)
            else:
                msg = f"{self.MY_DEVICE_IP} - ⚠️ Prediction failed: {response.status_code}"
                logging.warning(msg)
                self.post_log_to_server("WARN", msg)
        except Exception as e:
            err = f"{self.MY_DEVICE_IP} - ❌ Prediction send failed: {str(e)}"
            logging.error(err)
            self.post_log_to_server("ERROR", err)

    def main(self):
        while self.running:
            try:
                packets = self.capture_packets()
                features = self.extract_features(packets)

                if features is None:
                    msg = f"{self.MY_DEVICE_IP} - No features extracted."
                    logging.warning(msg)
                    self.post_log_to_server("WARN", msg)
                    continue

                probabilities = self.model.predict_proba(features)[0]
                top5_indices = np.argsort(probabilities)[-5:][::-1]

                predicted_classes = []
                for idx in top5_indices:
                    class_name = self.label_encoder.inverse_transform([idx])[0]
                    confidence = float(probabilities[idx])
                    predicted_classes.append({
                        "label": class_name,
                        "probability": confidence
                    })

                # Metric extraction
                try:
                    flow_duration = float(features['Flow.Duration'].values[0])
                    total_packets = int(features['Total.Fwd.Packets'].values[0])
                    total_bytes = int(features['Total.Length.of.Fwd.Packets'].values[0])
                    average_packet_size = float(features['Average.Packet.Size'].values[0])
                    packet_rate = float(features['Flow.Packets.s'].values[0])
                    byte_rate = float(features['Flow.Bytes.s'].values[0])
                except Exception as metric_error:
                    logging.error(f"❌ Metric extraction failed: {str(metric_error)}")
                    flow_duration = total_packets = total_bytes = 0
                    average_packet_size = packet_rate = byte_rate = 0.0

                payload = {
                    "sourceIP": self.last_src_ip or "Unknown",
                    "destinationIP": self.last_dst_ip or "Unknown",
                    "sourcePort": 0,
                    "destinationPort": 0,
                    "predictedClass": {
                        "classes": predicted_classes
                    },
                    "confidence": float(probabilities[top5_indices[0]]),
                    "metrics": {
                        "flowDuration": flow_duration,
                        "totalPackets": total_packets,
                        "totalBytes": total_bytes,
                        "averagePacketSize": average_packet_size,
                        "packetRate": packet_rate,
                        "byteRate": byte_rate
                    }
                }

                self.executor.submit(self.send_prediction, payload)

                msg = f"{self.MY_DEVICE_IP} - 🔥 Most likely traffic: {predicted_classes[0]['label']} 🔥"
                logging.info(msg)
                self.post_log_to_server("INFO", msg)

            except Exception as e:
                err = f"{self.MY_DEVICE_IP} - Error during service loop: {str(e)}"
                logging.error(err)
                self.post_log_to_server("ERROR", err)

            time.sleep(5)


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(TrafficClassifierService)
