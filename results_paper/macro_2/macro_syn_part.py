
import matplotlib
from matplotlib import pyplot as plt
from csv import DictReader

replay = {}
replay[1000] = []
replay[1500] = []
replay[2000] = []

p = range(0, 11)

with open("10000x9999x1000_defrag.csv") as f:
    for line in f:
        items = line.split(',')
        replay[1000].append(float(items[3]))
with open("10000x9999x1500.csv") as f:
    for line in f:
        items = line.split(',')
        replay[1500].append(float(items[3]))
with open("10000x9999x2000.csv") as f:
    for line in f:
        items = line.split(',')
        replay[2000].append(float(items[3]))

#p_text = ["1k", "5k", "10k", "50k", "100k", "500k", "1M"]
#y_text = []
#p = [1000, 5000, 10000, 50000, 100000, 500000, 1000000]


fig, ax1 = plt.subplots(figsize=(6,2.5))
ax1.plot(p, replay[1000], marker="v", markersize=8, label="IBBE-SGX-1000")
ax1.plot(p, replay[1500], marker="s", markersize=8, label="IBBE-SGX-1500")
ax1.plot(p, replay[2000], marker="o", markersize=8, label="IBBE-SGX-2000")
#ax1.plot(p, create[3000], '-', marker="^", markersize=8)
#ax1.plot(p, create[4000], '--', marker="+", markersize=8)
#ax1.plot(p, rsa, '--', marker="+", markersize=8)

#ax1.legend(loc=2, ncol=3)
#bbox_to_anchor=(0,1.02,1,0.2), loc="lower left",
#                mode="expand", borderaxespad=0, ncol=3)

ax1.set_xlabel('revocation ratio %')
ax1.set_ylabel('total replay time (s)')


#ax1.set_yticks()

plt.xticks([1, 3, 5, 7, 9], ["10%", "30%", "50%", "70%", "90%"])
#plt.yticks([0.001, 0.01, 0.1, 1, 5], ["0.001", "0.01", "0.1", "1", "5"])

axes = plt.gca()
axes.set_xlim([-0.1,10.1])
axes.set_ylim([0, 210])

#plt.grid()


plt.tight_layout()
plt.show()
