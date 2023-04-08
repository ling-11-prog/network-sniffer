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

#from scapy.layers.http import HTTPRequst
from demo2 import session_GUI
from demo3 import track_tcp_GUI
# show_interfaces()
show_interfaces()
# packets = sniff(count=10, iface="Realtek 8822BE Wireless LAN 802.11ac PCI-E NIC")
# number=0
# for packet in packets:
#     print(packet)
#     packet.show()

class GUI:
    def __init__(self):
        self.root= Tk()
        self.root.title('网络嗅探工具')
        self.root.geometry('900x600') # 这里的乘号不是 * ，而是小写英文字母 x
        self.frame0= tk.Frame(self.root,bd=5,relief	= 'sunken')
        self.frame0.place(x=10,y=0,width=880,height=100,)
        #self.frame0.config(bg='blue')
        self.frame1 = tk.Frame(self.root,bd=5,relief	= 'sunken')
        self.frame1.place(x=10,y=100,width=880,height=150,)
        #设定黄色，以确定我实际发生测试的区域
        #self.frame1.config(bg='yellow')

        self.frame2 = tk.Frame(self.root,bd=5,relief	= 'sunken')
        self.frame2.place(x=10,y=260,width=880,height=180,)
        #设定黄色，以确定我实际发生测试的区域
        #self.frame2.config(bg='blue')

        self.frame3 = tk.Frame(self.root,bd=5,relief	= 'sunken')
        self.frame3.place(x=10,y=450,width=880,height=140,)
        #设定黄色，以确定我实际发生测试的区域
        #self.frame3.config(bg='yellow')
        self.packet_handling=None
        self.packet_queue=Queue()
        #self.tabel_frame = Frame(self.root)#Frame
        #self.tabel_frame.pack()
        self.filemenu()
        self.filter()
        self.interface()#网卡多选框
        self.sniffer= None 
        self.button()
        self.packet_list()
        self.tree_layer()
        self.hex_content()
        #self.update_layer_list(packet)
        self.packets=[]
        self.count=0
    def filemenu(self):
        mainmenu = tk.Menu(self.root)
        filemenu=tk.Menu(mainmenu,tearoff=False)
        filemenu2=tk.Menu(mainmenu,tearoff=False)
        filemenu3=tk.Menu(mainmenu,tearoff=False)
        filemenu.add_command (label="介绍",command=self.menuCommand)
        filemenu.add_separator()
        filemenu.add_command (label="退出",command=self.root.quit)
        mainmenu.add_cascade (label="文件",menu=filemenu)

        filemenu2=tk.Menu(mainmenu,tearoff=False)
        filemenu2.add_command (label="以太网统计",command=self.session)
        filemenu2.add_command (label="IP统计",command=self.session_IP)
        mainmenu.add_cascade (label="统计",menu=filemenu2)

        filemenu3=tk.Menu(mainmenu,tearoff=False)
        filemenu3.add_command (label="追踪TCP流",command=self.track_tcp)
        mainmenu.add_cascade (label="分析",menu=filemenu3)

        self.root.config (menu=mainmenu)
    def menuCommand(self):
        tk.messagebox.showinfo(title='提示', message='抓包程序')
    def session(self):
        session_GUI(self.packets,1)
    def session_IP(self):
        session_GUI(self.packets,2)
        pass
    def track_tcp(self):
        itm = self.table.set(self.table.focus())
        print(itm)
        if not itm:
            tk.messagebox.showinfo(title='提示', message='请选择数据包后再追踪流')
            return
        packet=self.packets[eval(itm['No'])-1]
        print(packet)

        track_tcp_GUI(self.packets,packet)
        #先获取五元组:

        pass
    def filter(self):#失去焦点时，进行验证
        Dy_String = tk.StringVar()
        self.entry1 = tk.Entry(self.frame0,textvariable =Dy_String)#,validate ="focus",validatecommand=self.check_filter)
        self.entry1.bind("<FocusOut>", self.check_filter) 
        self.entry1.place(relx=0.1,rely=0.6,relwidth=0.7)
        self.label1=Label(self.frame0,text="捕获过滤:",font =("微软雅黑",10),)
        self.label1.place(relx=0.01,rely=0.6)
    def check_filter(self,e):
        filter_s=self.entry1.get().strip()
        # if filter_s=='':
        #     self.entry1.configure(bg="")
        if filter_s=='':
            self.entry1.configure(bg="white")
            return
        try:
            compile_filter(filter_exp=filter_s)
            self.entry1.configure(bg="green")
        except:
            self.entry1.configure(bg="red")
            return
    def button(self):
        self.Button0 = tk.Button(self.frame0, text="Start",command=self.get_packet)
        self.Button0.place(relx=0.85,rely=0.55,relwidth=0.05)
    def interface(self):
        #网卡选项
        var = StringVar()
        ifaces_list=[]
        for face in get_working_ifaces():
            ifaces_list.append(face.name)
        print(ifaces_list)
        self.comb = Combobox(self.frame0,textvariable=var,values=ifaces_list)
        self.comb.place(relx=0.1,rely=0.2,relwidth=0.7)
        self.label1=Label(self.frame0,text="网卡选择:",font =("微软雅黑",10),)
        self.label1.place(relx=0.01,rely=0.2)
        #self.comb.bind('<<ComboboxSelected>>',self.choose_iface)
        #流量列表
    #获取选择的网卡
    def choose_iface(self):
        iface_index=self.comb.current()
        if iface_index==-1:#没选择网卡
            return None
        iface=get_working_ifaces()[iface_index]
        print(iface)
        return iface
    def packet_list(self):
        columns=['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length','Info']

        sl = Scrollbar(self.frame1)
        sl.pack(side = RIGHT,fill = Y)

        self.table = Treeview(
            master=self.frame1,  # 父容器
            height=6,  # 表格显示的行数,height行
            columns=columns,  # 显示的列
            show='headings',  # 隐藏首列
            yscrollcommand=sl.set
            )
        sl['command'] = self.table.yview
        
        #ybar.grid(row=2,column=2,sticky='ns') 
        self.table.bind("<<TreeviewSelect>>",self.onSelect_packet_list)
        self.table.heading(column='No', text='No', anchor='w',
                  command=lambda: print('No'))  # 定义表头
        self.table.heading('Time', text='Time', )  # 定义表头
        self.table.heading('Source', text='Source', )  # 定义表头
        self.table.heading('Destination', text='Destination', )  # 定义表头
        self.table.heading('Protocol', text='Protocol', )  # 定义表头
        self.table.heading('Length', text='Length', )  # 定义表头
        self.table.heading('Info', text='Info', )  # 定义表头
        self.table.column('No', width=70, minwidth=70, anchor=S )  # 定义列
        self.table.column('Time', width=150, minwidth=150, anchor=S)  # 定义列
        self.table.column('Source', width=120, minwidth=120, anchor=S)  # 定义列
        self.table.column('Destination', width=120, minwidth=120, anchor=S)  # 定义列
        self.table.column('Protocol', width=70, minwidth=70, anchor=S)  # 定义列
        self.table.column('Length', width=70, minwidth=70, anchor=S)  # 定义列
        self.table.column('Info', width=250, minwidth=250, anchor=S)  # 定义列
        self.table.place(relx=0,rely=0)
    def onSelect_packet_list(self,e):
        itm = self.table.set(self.table.focus())
        print(itm)
        packet=self.packets[eval(itm['No'])-1]
        self.packet_handling=packet
        self.update_layer_list(packet)
        pass
    #抓包子进程
    def start(self):
        T1 = threading.Thread(name='t1', target=self.get_packet, daemon=True)  # 子线程
        T1.start()  # 启动
        
        # if self.sniffer:
        #     self.sniffer.stop()
        #     print('暂停抓包')
        #     return
    def get_packet(self):
        #
        if self.sniffer:

            self.sniffer.stop()
            self.sniffer = None
            self.Button0.configure(bg="red")
            self.Button0.configure(text="Strat")
            self.count=0

            return
        iface=self.choose_iface()
        filter_exp=self.entry1.get().strip()
        print(filter_exp)
        if iface is None:
            tk.messagebox.showinfo(title='提示', message='请先选择网卡')
            return
        self.sniffer = AsyncSniffer(
            iface=iface,
            prn=self.packet_analyse,
            filter=filter_exp,
        )
        #每次抓包都清空表格
        x=self.table.get_children()
        for item in x:
            self.table.delete(item)
        x=self.tree_layer.get_children()
        for item in x:
            self.tree_layer.delete(item)
        self.hex_text.delete(1.0,END)
        self.count=0
        self.packets=[]#清空缓存的数据包
        now_time = datetime.now().strftime( "%Y%m%d%H%M%S" )
        self.filename = "./pcaps/pcap{0}.pcap".format(now_time)
        self.sniffer.start()
        self.Button0.configure(bg="green")
        self.Button0.configure(text="Stop")
        print('开始抓包')
        #for index, data in enumerate(info):
        #    print(index)
        #    self.table.insert('', END, values=data)
    def packet_analyse(self,packet):

#filter = 'tcp.port == 2222'
        o_open_file= PcapWriter(self.filename, append=True)
        o_open_file.write(packet)
        self.packet_queue.put(packet)
        self.packets.append(packet)#将数据包添加到列表保存
        self.count+=1
        #info=[self.count,1,2,3,4,5,6]
        #self.table.insert('', END, values=info)
        time_show=datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
        #if package.hasLayer(HTTPRequest):
            #print(1)
        #print(packet.show())
        #子进程解析数据包
        for i in range(5):
            T1 = threading.Thread(name='t1', target=self.thread_handle_packet ,daemon=True)
            T1.start()
    def thread_handle_packet(self): 
        lock=threading.Lock()
        with lock:
            packet=self.packet_queue.get()  
            time_show=datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            else:
                src = packet.src
                dst = packet.dst
            layer = None
            for var in self.get_packet_layers(packet):
                if not isinstance(var, (Padding, Raw)):
                    layer = var
            if layer.name[0:3]=="DNS":
                protocol="DNS"
            else:
                protocol = layer.name
            length = f"{len(packet)}"
            try:
                info = str(packet.summary())
            except:
                info = "error"
            show_info=[self.count,time_show,src,dst,protocol,length,info]
            items=self.table.insert('', END, values=show_info)
            self.table.see(items)
    
    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1
    def tree_layer(self):
        self.tree_layer = Treeview(self.frame2,height=8,columns=('qy'),show='tree') 
        self.tree_layer.column('#0',width=650,stretch=False)
        self.tree_layer.place(relx=0.0,rely=0.0)
        s2 = Scrollbar(self.frame2)
        s2.pack(side = RIGHT,fill = Y)

        self.tree_layer['yscrollcommand']=s2.set
            
        s2['command'] = self.tree_layer.yview
        self.tree_layer.bind("<<TreeviewSelect>>",self.onSelect_tree_layer)
    def onSelect_tree_layer(self,e):
        item_id=self.tree_layer.focus()
        try:
            layer_name=self.tree_layer.item(item_id,option='text')#获取点击的是哪一层
        except:
            return
        packet=self.packet_handling
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            try:
                if layer.name==layer_name:
                    break
                if layer is None:
                    break
                counter += 1
            except:
                return
        self.hex_text.delete(1.0,END)
        self.hex_text.insert(INSERT,hexdump(layer, dump=True))

        #packet=self.packets[eval(itm['No'])-1]
        #self.update_layer_list(packet)
    def update_layer_list(self,packet): 
        #每次抓包都清空表格
        x=self.tree_layer.get_children()
        for item in x:
            self.tree_layer.delete(item)
        layer_name=[]
        counter = 0
        Ethernet_layer=packet.getlayer(0)
        self.hex_text.delete(1.0,END)
        if Ethernet_layer.name=='Ethernet':
            self.hex_text.insert(INSERT,hexdump(Ethernet_layer, dump=True))
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layer_name.append(layer)
            counter += 1
        parent_chile=[0,1,2,3,4,5,6,7,8,9,10,11]
        for index,layer in enumerate(layer_name):
            parent_chile[index]=self.tree_layer.insert("",index,text=layer.name)
            print(layer.name)
            for name, value in layer.fields.items():
                self.tree_layer.insert(parent_chile[index],index,text=f"{name}: {value}")
        

    def hex_content(self):
        #self.tree_layers = Treeview(self.frame3,height=7) 
        #self.tree_layers.place(relx=0.01,rely=0.01)

        self.hex_text = Text(self.frame3, width=121, height=9)
        self.hex_text.place(relx=0,rely=0)
        fontExample = tkFont.Font( size=10)

        self.hex_text.configure(font=fontExample)
        s3 = Scrollbar(self.frame3)
        s3.pack(side = RIGHT,fill = Y)

        self.hex_text['yscrollcommand']=s3.set
            
        s3['command'] = self.hex_text.yview
        #self.hex_text.grid()
        #self.hex_text.insert('1.0', '这是文本框,你可以输入任何内容')
if __name__ == '__main__':
    a = GUI()

    a.root.mainloop()