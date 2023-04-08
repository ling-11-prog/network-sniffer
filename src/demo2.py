from scapy.all import *

from queue import Queue
import os
import sys
import time
from tkinter import *
import tkinter as tk
from tkinter.ttk import *
from tkinter import ttk
import time
from datetime import datetime
import tkinter.messagebox 
import tkinter.font as tkFont
from scapy.arch.common import compile_filter

class session_GUI:
    def __init__(self,packets,flag):
        self.flag=flag
        self.root= Tk()
        if flag==1:
            self.root.title('Ethernet_Conversations')
        else:
            self.root.title('IP_Conversations')
        self.root.geometry('800x400') # 这里的乘号不是 * ，而是小写英文字母 x
        self.frame0= tk.Frame(self.root,bd=5,relief	= 'sunken')
        self.frame0.place(x=10,y=0,width=780,height=390,)
        self.show_details(packets)
        
                
    def show_details(self,packets):
        sl = Scrollbar(self.frame0)
        sl.pack(side = RIGHT,fill = Y)
        columns=['AddressA', 'AddressB', 'Packets', 'Bytes', 'PacketA->B', 'PacketB->A','BytesA->B','BytesB->A']
        self.table = Treeview(
            master=self.frame0,  # 父容器
            height=18,  # 表格显示的行数,height行
            columns=columns,  # 显示的列
            show='headings',  # 隐藏首列
            yscrollcommand=sl.set
            )
        sl['command'] = self.table.yview
        self.table.heading(column='AddressA', text='AddressA')  # 定义表头
        self.table.heading('AddressB', text='AddressB', )  # 定义表头
        self.table.heading('Packets', text='Packets', )  # 定义表头
        self.table.heading('Bytes', text='Bytes', )  # 定义表头
        self.table.heading('PacketA->B', text='PacketA->B', )  # 定义表头
        self.table.heading('PacketB->A', text='PacketB->A', )  # 定义表头
        self.table.heading('BytesA->B', text='BytesA->B', )  # 定义表头
        self.table.heading('BytesB->A', text='BytesB->A', )  # 定义表头
        self.table.column('AddressA', width=135, minwidth=135, anchor=S )  # 定义列
        self.table.column('AddressB', width=135, minwidth=135, anchor=S)  # 定义列
        self.table.column('Packets', width=60, minwidth=60, anchor=S)  # 定义列
        self.table.column('Bytes', width=60, minwidth=60, anchor=S)  # 定义列
        self.table.column('PacketA->B', width=90, minwidth=90, anchor=S)  # 定义列
        self.table.column('PacketB->A', width=90, minwidth=90, anchor=S)  # 定义列
        self.table.column('BytesA->B', width=92, minwidth=92, anchor=S)  # 定义列
        self.table.column('BytesB->A', width=90, minwidth=90, anchor=S)  # 定义列
        self.table.place(relx=0,rely=0)
        ip_address=[]
        packets_dic={}
        packets_info=[]
        if self.flag==1:#以太网会话
            for packet in packets:
                # if IP in packet:
                #     src = packet[IP].src
                #     dst = packet[IP].dst
                # else:
                #     src = packet.src
                #     dst = packet.dst
                addressa=packet.src
                addressb=packet.dst

                # addressa=src
                # addressb=dst
                packet_number=1
                packet_bytes=len(packet)
                if addressa+'-'+addressb not in packets_dic.keys():
                    packets_dic[addressa+'-'+addressb]=[packet_number,packet_bytes]
                else:
                    packets_dic[addressa+'-'+addressb][0]+=packet_number
                    packets_dic[addressa+'-'+addressb][1]+=packet_bytes
                #packets_info.append([addressa,addressb,packet,packet_bytes])
            show_list=[]
            key_del=[]
            for key,value in packets_dic.items():
                if key in key_del:
                    continue
                split=key.find('-')
                addressa=key[0:split]
                addressb=key[split+1:]
                if addressb+'-'+addressa in packets_dic.keys():
                    packets_number=value[0]+packets_dic[addressb+'-'+addressa][0]
                    packets_bytes=value[1]+packets_dic[addressb+'-'+addressa][1]
                    packetA2B=value[0]
                    packetB2A=packets_dic[addressb+'-'+addressa][0]
                    bytesA2B=value[1]
                    bytesB2A=packets_dic[addressb+'-'+addressa][1]
                    show_list.append([addressa,addressb,packets_number,packets_bytes,packetA2B,packetB2A,bytesA2B,bytesB2A])
                    key_del.append(key)
                    key_del.append(addressb+'-'+addressa)
                    # del dict[key]
                    # del dict[ddressb+'-'+addressa]
                else:
                    packets_number=value[0]
                    packets_bytes=value[1]
                    packetA2B=packets_number
                    packetB2A=0
                    bytesA2B=packets_bytes
                    bytesB2A=0
                    show_list.append([addressa,addressb,packets_number,packets_bytes,packetA2B,packetB2A,bytesA2B,bytesB2A])
                    key_del.append(key)
                    # del dict[key]
            print(show_list)
            for i in show_list:
                items=self.table.insert('', END, values=i)
        else:
            for packet in packets:
                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                else:
                    continue
                addressa=src
                addressb=dst

                    # addressa=src
                    # addressb=dst
                packet_number=1
                packet_bytes=len(packet)
                if addressa+'-'+addressb not in packets_dic.keys():
                    packets_dic[addressa+'-'+addressb]=[packet_number,packet_bytes]
                else:
                    packets_dic[addressa+'-'+addressb][0]+=packet_number
                    packets_dic[addressa+'-'+addressb][1]+=packet_bytes
                #packets_info.append([addressa,addressb,packet,packet_bytes])
            show_list=[]
            key_del=[]
            for key,value in packets_dic.items():
                if key in key_del:
                    continue
                split=key.find('-')
                addressa=key[0:split]
                addressb=key[split+1:]
                if addressb+'-'+addressa in packets_dic.keys():
                    packets_number=value[0]+packets_dic[addressb+'-'+addressa][0]
                    packets_bytes=value[1]+packets_dic[addressb+'-'+addressa][1]
                    packetA2B=value[0]
                    packetB2A=packets_dic[addressb+'-'+addressa][0]
                    bytesA2B=value[1]
                    bytesB2A=packets_dic[addressb+'-'+addressa][1]
                    show_list.append([addressa,addressb,packets_number,packets_bytes,packetA2B,packetB2A,bytesA2B,bytesB2A])
                    key_del.append(key)
                    key_del.append(addressb+'-'+addressa)
                        # del dict[key]
                        # del dict[ddressb+'-'+addressa]
                else:
                    packets_number=value[0]
                    packets_bytes=value[1]
                    packetA2B=packets_number
                    packetB2A=0
                    bytesA2B=packets_bytes
                    bytesB2A=0
                    show_list.append([addressa,addressb,packets_number,packets_bytes,packetA2B,packetB2A,bytesA2B,bytesB2A])
                    key_del.append(key)
                        # del dict[key]
            print(show_list)
            for i in show_list:
                items=self.table.insert('', END, values=i)
