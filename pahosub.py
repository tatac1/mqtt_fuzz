import paho.mqtt.client as mqtt

host = '127.0.0.1'
port = 1883
topic = 'Momo'

def on_connect(client, userdata, flags, respons_code):
    print ('status '+str(respons_code))
    client.subscribe(topic)

def on_message(client, userdata, msg):
    print(msg)

if __name__ == '__main__':
    client = mqtt.Client(protocol=mqtt.MQTTv311)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, port = port, keepalive=60)
    client.loop_forever()
