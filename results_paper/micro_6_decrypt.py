
import matplotlib
from matplotlib import pyplot as plt
from csv import DictReader

decrypt = []
rsa_dec = []

rsa_decrypt_value = 0.01

with open("6_decrypt.csv") as f:
    for line in f:
        items = line.split(',')
        decrypt.append(float(items[4]))
        rsa_dec.append(rsa_decrypt_value)

p_text = ["1k", "2k", "3k", "4k"]
p = [1, 2, 3, 4]

fig, ax1 = plt.subplots(figsize=(3,2.5))
ax1.plot(p, decrypt, marker="o", markersize=8, label="IBBE-SGX")
ax1.plot(p, rsa_dec, "--",marker="+", markersize=8, label="HE")


ax1.set_xlabel('partition size')
ax1.set_ylabel('latency (s)')

#ax2 = ax1.twinx()
#ax2.plot(p, extract,'--', marker="v", markersize=8)
#ax2.set_ylabel('throughput (op/s)')
#ax2.set_ylim(600, 900);

plt.xticks(p, p_text)

axes = plt.gca()
axes.set_xlim([0.7,4.3])


#ax1.hlines([0.01], [0], [4.3], lw=1, linestyle='dashed')

ax1.set_yscale('log')
plt.yticks([0.001, 0.1, 2], ["0.001", "0.1", "2"])

#plt.grid()

plt.legend(ncol=3)
#plt.show()

plt.tight_layout()
plt.show()
