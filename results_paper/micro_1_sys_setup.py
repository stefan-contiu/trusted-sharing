
import matplotlib
from matplotlib import pyplot as plt
from csv import DictReader

setup = []
extract = []
with open("1_pk_uk.csv") as f:
    for line in f:
        items = line.split(',')
        if (items[1] == "SETUP_SYS"):
            setup.append(float(items[4]))
        else:
            extract.append(float(items[4]))

p_text = ["1k", "2k", "3k", "4k"]
p = [1, 2, 3, 4]


fig, ax1 = plt.subplots(figsize=(3,2.5))

ax1 = plt.subplot()#211)
plt.plot(p, setup, marker="o", markersize=8)
#plt.setp(ax1.get_xticklabels(), visible=False)
ax1.set_ylim(0, 6);

ax1.set_ylabel('setup latency (s)')
ax1.set_xlabel('partition size')

ax2 = plt.subplot()#212) #, sharex=ax1)
plt.plot(p, extract, marker="v", markersize=8)
ax2.set_ylabel('key extract speed (op/s)')
ax2.set_ylim(600, 900);
# make these tick labels invisible

ax2.set_xlabel('partition size')

plt.xticks(p, p_text)

axes = plt.gca()
axes.set_xlim([0.7,4.3])

#plt.grid()

plt.tight_layout()
plt.show()
