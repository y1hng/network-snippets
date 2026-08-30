from scapy.all import *
import time
def icmp_pkt(target, max_hops=30):
    ips = []
    def icmp(TTl):
        return IP(dst=target, ttl=TTl) / ICMP()
    # هنا كتبنا IP بمعنا الطبقة 3 و ال dst جائت من كلمة الوجهة و ال ttl لاننا سنتلاعب ب قيمة ال ttl تم icmpلكي نجعل نوع الحزمة ICMP
    ttl = 1
    while ttl <= max_hops: #هنا ال كود يبقى يتكرر مادام مازال لم يصل ل ان يصبح ال ttl اكبر او يساوي عدد القفزات
        time.sleep(0.5) #هنا مهلة زمنية صغيرة بين الحزمة و الاخرى لكي لا يكون الامر سريعا جدا
        icmp_Pkt = icmp(ttl) #هنا وضعنا الحزمة هده داخلها قيمة ttl =1 
        try:
            reply = sr1(icmp_Pkt, timeout=2, verbose=False) # تم هنا وضعناها به و سنرسلها عبر sr1 التي تخص الطبقة 3 من الشبكات osi
        except (PermissionError, OSError):
            raise # هنا معالجة اخطاء ال صلاحيات و النظامم و ادا ظهر خطأ يتوقف السكريبت تماما
        if reply  is not None and reply.haslayer(ICMP):
            #هنا ادا كان الرد ليس لا شيئ و الرد من نوع icmp قم ب
            src_ip = reply.src #انشاء متغيرة ال عنوان ال IP 
            icmp_type = reply[ICMP].type # هنا نوع الحزمة
            if icmp_type == 11: # هنا ادا كان الرد نوع 11 يعني ان الحزمة ماتت بسبب انتهاء قيمة ttl ف يضيف دالك العنوان للقائمة تم يقوم ب المرور للاسفل
                if src_ip not in ips:
                    ips.append(src_ip)
            elif icmp_type == 0: # او ادا كانت الحزمة تحمل قيمة 0 فنحن وصلنا للوجهة ف نضيف ال ip تم نتوقف
                if src_ip not in ips:
                    ips.append(src_ip)
                break
            ttl += 1 # يضيف الttl + 1 لكي يتجاوز هدا الرد و يتجاوز القفزة تلك بدلا من نفس الرد
        return ips

IPS = icmp_pkt('192.168.57.1')
for ip in IPS:
    print(f'* {ip}\n')
