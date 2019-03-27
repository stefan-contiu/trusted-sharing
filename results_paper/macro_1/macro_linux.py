
import matplotlib
from matplotlib import pyplot as plt
from csv import DictReader

replay_ibbe_sgx = []
decrypt = []
he_r = []
he_replay = 2650.625275
he_decrypt = 0.01
he_d = []
lim_left = 100
lim_right = 3750-100


p = [250, 500, 750, 1000, 1250, 1500, 1750, 2000, 2250, 2500, 2750, 3000, 3250, 3500]

for x in range(0, len(p)):
    he_r.append(he_replay)
    he_d.append(he_decrypt)

# read IBBE-SGX
with open("linux_replay.csv") as f:
    for line in f:
        items = line.split(',')
        replay_ibbe_sgx.append(float(items[2]))

# read decrypt
with open("decrypt.csv") as f:
    for line in f:
        items = line.split(',')
        decrypt.append(float(items[2]))


fig, ax1 = plt.subplots(figsize=(6,2.5))
#fig, ax1 = plt.subplots()
replay_line = ax1.plot(p, replay_ibbe_sgx, marker="^", markersize=8, label='IBBE-SGX Total Replay Time')

ax1.plot(p, he_r,   '--',marker="s", markersize=8, label='HE Total Replay Time')
ax1.set_ylabel('total replay time (s)')
#plt.legend(loc=2)

ax2 = ax1.twinx()
decrypt_line = ax2.plot(p, decrypt, marker="o", markersize=8, label='IBBE-SGX Avg Decrypt Time')
ax2.set_ylabel('avg decrypt time (s)')
ax2.plot(p, he_d, '--', marker="+", markersize=8, label='HE Avg Decrypt Time')
#plt.legend(loc=2, ncol=1)

ax1.set_xlabel('partition size')
axes = plt.gca()
axes.set_xlim([lim_left,lim_right])

#plt.grid()

 #, decrypt_line])
plt.tight_layout()
plt.show()
