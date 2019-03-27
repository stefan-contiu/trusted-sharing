
import matplotlib
from matplotlib import pyplot as plt
from csv import DictReader

remove = {}
remove[1000] = []
remove[2000] = []
remove[3000] = []
remove[4000] = []
rsa_remove = []

with open("4_remove.csv") as f:
    for line in f:
        items = line.split(',')
        remove[int(items[3])].append(float(items[4]))

# read PKI
with open("rsa_all.csv") as f:
    for line in f:
        items = line.split(',')
        if (items[1] == "REMOVE"):
            rsa_remove.append(float(items[4]))


p_text = ["1k", "5k", "10k", "50k", "100k", "500k", "1M"]
p = [1, 2, 3, 4, 5, 6, 7]

fig, ax1 = plt.subplots(figsize=(4,2.5))
ax1.plot(p, remove[1000], '--', marker="v", markersize=8)
ax1.plot(p, remove[2000], marker="o", markersize=8)
ax1.plot(p, remove[3000], '-', marker="^", markersize=8)
ax1.plot(p, remove[4000], '--', marker="+", markersize=8)
ax1.plot(p, rsa_remove, '--', marker="+", markersize=8)

ax1.set_xlabel('group size')
ax1.set_ylabel('latency (s)')

ax1.set_yscale('log')
#ax1.set_yticks([0.001, 1, 20])
plt.yticks([0.001, 0.01, 0.1, 1, 50], ["0.001", "0.01", "0.1", "1", "50"])

plt.xticks(p, p_text)

axes = plt.gca()
#axes.set_xlim([0.7,4.3])

plt.grid()

plt.tight_layout()
plt.show()
