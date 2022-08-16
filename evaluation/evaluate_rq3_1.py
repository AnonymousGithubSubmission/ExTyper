from collections import defaultdict
from email.policy import default



projects = ['seagull','tinychain','relex','htmlark', 'pendulum', 'adventure', 'imp', 'chip', 'scion', 'unittests'][:5]
returnses = [
[3,5,8,10,12,14,16,18,20,22,24,26,31,35,37,39,40,41,43,47,48,49,50,51,52,53,55,56,57,58,59,60,61,64,65,66,67,68,69],
[3,6,9,10,12,15,18,19,21,22,28,31,34,36,39,40,42,47,51,53,55,57,59,62,64,66,68,70,72,77,80,81,83,85,88,91,94,97,100,103],
[10, 17, 20, 23, 26, 28, 33, 36, 38, 40, 47, 49, 51],
[2, 4, 7, 15, 16], 
[2,5,8,10,12,14,16,20,21,22,23,24,25,27,29,31,34,36,37,40,43,44,47,50,51,54,59,60,61,62,65,72,73,74,75,76,77,78,81,83,86,88,90,92,94,97,98,99,101,105,107,109,113,117,120,124,125,126,127,128,129,130,131,133,135,136,138,139,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,165,166,167,169,171,172,173,175,177,179,181,183,188,193,195,197,198,199,201,203,204,206,208,212,213,214,215,220,222,224,226,229,231,233,236,239,242,245,249,251,254,257,258,261,264,269,274,276,278,280,282,284,287,291,297,298,300,301,303,307,308,309,310,311,312,313,314,315,316,317,318,319,320,323,326,327,328,330,332,334,335,337,339,341,343,345,346,347,348,350,352,353,355,356,358,367,368,369,370,371,372,373,374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 387, 392, 394, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 413, 414, 415, 419, 423, 424, 425, 426, 428, 430, 432, 434, 437, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 462, 465, 467, 469, 472, 474, 476, 479, 481, 483, 486, 488, 490, 492, 494, 496, 499, 501, 503, 506, 508, 509, 511, 512, 514, 517, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 534, 537, 538, 539, 540, 541, 543, 545, 550, 555, 557, 559, 561, 563, 566, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 584, 586, 588, 590, 593, 595, 597, 600, 602, 604, 607, 609, 613, 616, 617, 620, 628, 631, 633, 636, 638, 640, 642, 644, 645, 646, 649, 650, 652, 654, 656, 658, 660, 661, 663, 664, 665, 666, 667, 669, 671, 674, 676, 679, 680, 682, 683, 685, 689, 691, 694, 697, 700, 703, 707, 709, 712, 715, 717, 727, 735, 743, 747, 752, 754, 756, 758, 760, 763, 773],
[2,3,4,5,6,7,8,9,10,11,12,13,14,16,18,19,20,22,23,24,25,26,28,30,31,33,34,35,36,38,42,44,48,52,56,61,65,69,73,78,82,86,90,97,],

[2,5,7,8,10,12,14,16,19,22,25,28,31,34,37,40,43,46,48,50,51,53,54,56,57,59,60,62,63,65,66,68,69,71,72,74,75,77,78,80,81,83,85,87,88,89,90,92,93,95,96,98,99,100,101,102,103,104,105,106,107,108,111,115,117,119,121,123,],
[2,3,4,5,7,8,9,10,11,12,13,15,17,19,20,21,22,25,29,30,33,35,36,37,38,39,40,42,43,44,46,47,49,51,53,55,],
[2,4,6,8,10,13,14,15,16,18,20,22,23,24,25,26,27,28,31,34,35,37,38,40,41,42,44,46,48,49,51,53,57,59,61,63,64,66,68,69,71,72,73,74,75,76,79,81,82,84,86,], 
[2,3,4,5,6,7,8,10,12,14,16,17,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,53,54,56,58,59,60,62,64,66,68,70,72,73,74,75,76,78,79,81,82,84,87,88,89,90,91,93,95,97,99,101,103,105,107,109,110,111,112,113,115,117,119,121,123,125,127,129,131,133,135,137,139,140,141,143,147,148,154,156,158,162,163,166,168,170,171,173,174,176,177,179,180,182,183,185,186,188,189,191,192,194,195,197,198,200,201,203,205,208,211,212,213,215,216,218,220,222,225,229,231,233,235,238,240,242,244,246,248,251,254,256,260,261,262,263,264,265,266,267,268,270,272,274,276,277,278,280,281,282,283,284,286,289,291,294,297,299,302,303,],
][:5]

models = ['pytype', 'typilus', 'TW', 'pyre', 'PIG']
pytype_times = [17.5,16.2,88.0,9.8,162.41,4.49,7.13,10.402,11.222,64.53][:5]
typilus_times = [4.2,4.0,3.7,3.3,6.36,3.9,3.81,3.66,3.62,4.93][:5]
TW_times = [7.5,7.7,7.3,7.0,59.48,7.617,7.76,7.41,8.34,33.09][:5]
PIG_times = [6.2, 49.5, 66.4, 1.6, 599.8, 46.7, 7.26, 4.02, 4.84, 18.96][:5]
pyre_times = [1.46, 1.47, 1.44, 1.43, 2.35, 1.44, 1.40,1.46,1.85,1.95][:5]
model_times = {'pytype':pytype_times,'typilus':typilus_times, 'TW':TW_times, 'PIG':PIG_times, 'pyre': pyre_times}
Tot = []
Avg = []
for i, proj in enumerate(projects):
    funcs = returnses[i]
    func_num = len(funcs)
    for model in models:
        total_time = model_times[model][i]
        avg_time = total_time/func_num
        Tot.append('{:.2f}'.format(round(total_time, 2)))
        Avg.append('{:.2f}'.format(round(avg_time, 2)))
    # s = set()
    # with open(f'result/data-benchmark-unittests-{proj}.py_whole_') as f:
    #     for l in f:
    #         s.add(l.strip())
    # nou = len(s)
    # rou = nou/func_num
    # print(nou)
    # print(rou)
    

# print(Tot)
# print(Avg)


with open('table_rq3.txt', 'w+') as f:

    f.write('Tot. & ' + ' & '.join(Tot) + '\\\\ \\hline' +'\n')
    f.write('Avg. & ' + ' & '.join(Avg) + '\\\\ \\hline' +'\n')




