import dpkt 
import time
import argparse
import socket
import os
from operator import itemgetter

runmode = 'stats'    #    options are: 'stats' OR 'sample'

stats_total_packets = 0
stats_total_bytes   = 0

stats = {
  # "ipv4_addr":[pkt_sent,pkt_recv,pkt_total,bytes_sent,bytes_recv,bytes_total,bytes_dest_port:{'53':346,...}]
  # bytes_dest_port only applies to when the ipv4_addr is in the ip.dst field (for traffic going to this ip)
}

def print_logo():
  print("Yet another PCAP tool")


def init():
  return

def update_stats(src_ip,dest_ip,pkt_bytes,dest_port):

  global stats_total_packets
  global stats_total_bytes
  global stats

  stats_total_packets = stats_total_packets + 1
  stats_total_bytes   = stats_total_bytes + pkt_bytes

  # need to process both source and destination ip for stats

  if src_ip in stats:
    stats[src_ip][0] = stats[src_ip][0]+1
    stats[src_ip][2] = stats[src_ip][2]+1
    stats[src_ip][3] = stats[src_ip][3]+pkt_bytes
    stats[src_ip][5] = stats[src_ip][5]+pkt_bytes
  else:
    bdp = {}
    stats[src_ip] = [1,0,1,pkt_bytes,0,pkt_bytes,bdp]

  # "ipv4_addr":[pkt_sent,pkt_recv,pkt_total,bytes_sent,bytes_recv,bytes_total,bytes_dest_port:{'53':346,...}]

  if dest_ip in stats:
    stats[dest_ip][1] = stats[dest_ip][1]+1
    stats[dest_ip][2] = stats[dest_ip][2]+1
    stats[dest_ip][4] = stats[dest_ip][4]+pkt_bytes
    stats[dest_ip][5] = stats[dest_ip][5]+pkt_bytes
    if dest_port is not None:
      if dest_port in stats[dest_ip][6]:
        stats[dest_ip][6][dest_port] = stats[dest_ip][6][dest_port] + pkt_bytes 
      else:
        stats[dest_ip][6][dest_port] = pkt_bytes
  else:
    bdp = {}
    if dest_port is not None:
      bdp[dest_port] = pkt_bytes
    stats[src_ip] = [1,0,1,pkt_bytes,0,pkt_bytes,bdp]

# expects the Ethernet packet (preparsed by dpkt)
def process_packets(pkt):
  
  dest_port = None

  try:
    ip_payload = pkt.data
    src_ip  = socket.inet_ntoa(ip_payload.src)
    dest_ip = socket.inet_ntoa(ip_payload.dst)
    packet_bytes = len(pkt.data)
  except:
    return # cannot parse IP, no need to continue

  try:
    tcp_payload = ip_payload.tcp 
    dest_port = tcp_payload.dport
  except:
    pass

  try:
    udp_payload = ip_payload.udp
    dest_port = udp_payload.dport
  except:
    pass

  update_stats(src_ip,dest_ip,packet_bytes,dest_port)
  return

def PrettyRelativeTime(time_diff_secs):
    # Each tuple in the sequence gives the name of a unit, and the number of
    # previous units which go into it.
    weeks_per_month = 365.242 / 12 / 7
    intervals = [('minute', 60), ('hour', 60), ('day', 24), ('week', 7),
                 ('month', weeks_per_month), ('year', 12)]

    unit, number = 'second', abs(time_diff_secs)
    for new_unit, ratio in intervals:
        new_number = float(number) / ratio
        # If the new number is too small, don't go to the next unit.
        if new_number < 2:
            break
        unit, number = new_unit, new_number
    shown_num = int(number)
    return '{} {}'.format(shown_num, unit + ('' if shown_num == 1 else 's'))

def show_progress(started,file_size):
  tn = time.time()
  elapsed = tn-started
  remain = file_size - stats_total_bytes
  eta = (remain * elapsed)/stats_total_bytes
  print("\033[A{}\033[A".format(''.join([' ']*50)))
  print('\033[35m⌛\033[39m Please wait, remaining: {0:s}, speed: {1:,.2f}MB/s'.format(PrettyRelativeTime(eta),stats_total_bytes/1024/1024/elapsed))

# print the statistic
def print_stat(key,top):
  global stats
  stat = [] # each array element is {'ip':IP,'key':VALUE}
  map = {
    'pkt_sent'   :0,
    'pkt_recv'   :1,
    'pkt_total'  :2,
    'bytes_sent' :3,
    'bytes_recv' :4,
    'bytes_total':5
  }
  i = map[key]
  for key_ip in stats:
    stat.append({'ip':key_ip,key:stats[key_ip][i]})
  stat2 = sorted(stat, key=itemgetter(key), reverse=True)
  print("Id\tIP            \t\t{}".format(key))
  for j in range(top):
    print("{}\t{}\t\t{}".format(j,stat2[j]['ip'],stat2[j][key]))

def main():
  
  global stats_total_packets

  print_logo()
  init()
  
  # parse cmd line args

  argparser = argparse.ArgumentParser()
  argparser.add_argument('--input', dest='file', default=None, required=True,
                           help='Specify the name of the pcap file to read.')
  argparser.add_argument('--mode', dest='mode', default='stats', choices=['stats'], type=str,
                           help='Select which operation to perform on the input file. Default is stats.')
  argparser.add_argument('--top', dest='top', default='10', type=int,
                           help='How many entries to show for statistics. Used with for stats mode. Default is 10.')
  argparser.add_argument('--column', dest='column', default='bytes_total', type=str, choices=['pkt_sent','pkt_recv','pkt_total','bytes_sent','bytes_recv','bytes_total'],
                           help='Which column to sort on. Default is `bytes_total`. Sort is always descending.')

  args = argparser.parse_args()

  start = time.time()

  if args.file: 
    print('\033[35m🔎\033[39m reading pcap file: {}\n'.format(args.file))
    f_size = os.stat(args.file).st_size
    f = open(args.file,'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
      eth = dpkt.ethernet.Ethernet(buf)
      process_packets(eth)
      if stats_total_packets % 10000 == 0: # refresh stats every 10000 packets
        show_progress(start,f_size)

    f.close()

  end = time.time()

  if 'stats' in args.mode:
    # display the resulting statitistics
    print('Total packets read: {}'.format(stats_total_packets))
    print('Total execution time: {}'.format(PrettyRelativeTime(end - start)))
    # TODO: check args before calling
    print_stat(args.column,args.top)

main()
