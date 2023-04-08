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

class track_tcp_GUI:
    def __init__(self,packets,packet):
        self.root= Tk()
        self.root.title('flow_information')
        self.root.geometry('800x400') # 这里的乘号不是 * ，而是小写英文字母 x
        self.frame0= tk.Frame(self.root,bd=5,relief	= 'sunken')
        self.frame0.place(x=10,y=0,width=780,height=200,)
        self.frame1= tk.Frame(self.root,bd=5,relief	= 'sunken')
        self.frame1.place(x=10,y=205,width=780,height=190,)       
        #self.show_details(packets)
        #self.show_track(packets,packet)
        self.packets=packets
        self.packet=packet
        self.table()
        self.hex_content()
    def table(self):

        columns=['No', 'Source', 'Destination', 'Source_port', 'Destitation_port', 'Protocol','Length']
        sl = Scrollbar(self.frame0)
        sl.pack(side = RIGHT,fill = Y)
        self.table = Treeview(
            master=self.frame0,  # 父容器
            height=8,  # 表格显示的行数,height行
            columns=columns,  # 显示的列
            show='headings',  # 隐藏首列
            yscrollcommand=sl.set
            )
        sl['command'] = self.table.yview

        self.table.bind("<<TreeviewSelect>>",self.updata_hex)
        self.table.heading(column='No', text='No',)
        self.table.heading('Source', text='Source', )  # 定义表头
        self.table.heading('Destination', text='Destination', )  # 定义表头
        self.table.heading('Source_port', text='Source_port', )  # 定义表头
        self.table.heading('Destitation_port', text='Destitation_port', )  # 定义表头
        self.table.heading('Protocol', text='Protocol', )  # 定义表头
        self.table.heading('Length', text='Length', )  # 定义表头

        self.table.column('No', width=67, minwidth=67, anchor=S )  # 定义列
        self.table.column('Source', width=150, minwidth=150, anchor=S)  # 定义列
        self.table.column('Destination', width=120, minwidth=120, anchor=S)  # 定义列
        self.table.column('Source_port', width=120, minwidth=120, anchor=S)  # 定义列
        self.table.column('Destitation_port', width=120, minwidth=120, anchor=S)  # 定义列
        self.table.column('Protocol', width=90, minwidth=90, anchor=S)  # 定义列
        self.table.column('Length', width=80, minwidth=80, anchor=S)  # 定义列
        self.table.place(relx=0,rely=0)
        self.show_track()

    def show_track(self):
        packets=self.packets
        packet=self.packet

        show_list=[]
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = packet.src
            dst = packet.dst
        protocol='TCP'
        sport=packet['TCP'].sport
        dport=packet['TCP'].dport
        for index,i in enumerate(packets):
            try:
                if i['TCP']:
                    if IP in i:
                        src_i = i[IP].src
                        dst_i = i[IP].dst
                    else:
                        src_i = i.src
                        dst_i = i.dst
                    if (i['TCP'].sport==sport and i['TCP'].dport==dport and src_i==src and dst_i==dst):
                        show_list.append([index,src_i,dst_i,sport,dport,'TCP',(len(i))])
                    elif (i['TCP'].sport==dport and i['TCP'].dport==sport and src_i==dst and dst_i==src):
                        show_list.append([index,src_i,dst_i,dport,sport,'TCP',(len(i))])
            except:
                continue
        for i in show_list:
            items=self.table.insert('', END, values=i)
    def hex_content(self):
        #self.tree_layers = Treeview(self.frame3,height=7) 
        #self.tree_layers.place(relx=0.01,rely=0.01)

        self.hex_text = Text(self.frame1, width=107, height=14)
        self.hex_text.place(relx=0,rely=0)
        #fontExample = tkFont.Font( size=1)

        #self.hex_text.configure(font=fontExample)
        s3 = Scrollbar(self.frame1)
        s3.pack(side = RIGHT,fill = Y)

        self.hex_text['yscrollcommand']=s3.set
            
        s3['command'] = self.hex_text.yview
    def updata_hex(self,e):
        itm = self.table.set(self.table.focus())
        print(itm)
        packet=self.packets[eval(itm['No'])-1]
        Ethernet_layer=packet.getlayer(0)
        self.hex_text.delete(1.0,END)
        self.hex_text.insert(INSERT,hexdump(Ethernet_layer, dump=True))