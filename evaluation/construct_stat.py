from email.policy import default
from random import choice, choices
import os
import ast
from klara.core.cfg import Cfg
from klara.core.tree_rewriter import AstBuilder
from textwrap import dedent
from collections import defaultdict, deque
import re
from prettytable import PrettyTable
from run_unittest_on_metric import fis, packages, ds, pk, remove_any, remove_nan, remove_none, same_ds, same_ds_, same_pk, same_pk_, same_type_recall, same_type, pure, real_name, read_ret

builtins = ['int', 'float','bool','str', 'byte', 'callable', 'none', 'object']
third = ['ndarray', 'tensor', 'namespace', 'vocabulary', 'textfieldembedder', 'jsondict', 'instance', 'socket', 'token']

projects = ['seagull','tinychain','relex','htmlark', 'pendulum', 'adventure', 'imp', 'icemu', 'scion', 'test_suite']
# projects = ['ut']
# returnses = [
# [0, 2, 4, 6, 9, 11, 13, 15, 18, 19, 21, 25, 27, 29, 30, 32, 34, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 59, 61, 63, 65],
# [0,1,2,3,5,7,8,10,13,16,19,22,23,25,26,27,33,36,39,41,44,45,47,48,53,57,62,64,66,68,70,73,76,79,82,85,88,90,93,95,97,98,100,102,104,],
# [0, 2, 9, 11, 13, 16, 23, 25, 28, 31, 33, 34],
# [0, 1, 3, 6, 14, 15],
# [0,3,6,7,8,9,10,11,13,15,17,20,21,24,26,27,30,31,34,35,36,37,40,41,42,43,44,45,46,48,51,53,55,57,59,60,61,62,63,64,65,66,67,69,71,72,74,75,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,101,102,103,105,107,108,109,111,113,115,117,122,123,126,129,134,139,141,143,145,147,149,152,156,162,163,165,166,168,169,170,171,172,173,174,175,176,177,178,179,180,181,184,187,188,189,191,193,195,196,198,200,202,204,206,207,208,209,211,213,214,216,217,219,224,226,228,229,230,232,234,235,237,239,248,249,250,251,252,253,254,255,256,257,258,259,260,261,262,263,264,265,269,274,276,278,279,280,281,282,283,284,285,286,287,288,289,290,291,292,295,296,297,301,305,306,307,308,310,312,321,330,332,334,337,341,342,343,344,345,346,347,348,349,350,351,352,353,354,355,356,357,358,359,362,365,367,369,372,374,376,379,381,383,386,388,390,392,394,396,398,399,401,402,404,407,411,412,413,414,415,416,417,418,419,420,421,424,427,428,429,430,431,433,435,440,445,447,449,451,453,456,460,461,462,463,464,465,466,467,468,469,470,471,472,474,476,478,480,483,485,487,490,492,494,497,499,503,504,507,515,518,520,523,525,527,529,531,532,533,534,537,539,541,543,545,547,548,549,550,551,552,554,556,557,558,559,564,566,568,571,573,575,578,581,584,587,591,593,596,599,602,604,605,608,609,611,612,614,618,620,623,626,629,632,634,637,], 
# [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 16, 18, 19, 21, 22, 23, 24, 26, 28, 30, 34, 36, 40, 44, 48, 53, 57, 61, 65, 70, 74, 78, 82, 89],
# [0, 3, 5, 6, 8, 10, 12, 14, 17, 20, 23, 26, 29, 32, 35, 38, 41, 44, 46, 48, 49, 51, 52, 54, 55, 57, 58, 60, 61, 63, 64, 66, 67, 69, 70, 72, 73, 75, 76, 78, 79, 81],
# [0,1,2,3,5,6,7,8,9,10,11,13,17,18,19,20,22,24,27,29,30,34,35,38,40,41,42,43,44,45,47,48,50,51,53,54,56,58,60,62,],
# [0, 2, 4, 6, 8, 11, 12, 13, 14, 16, 18, 20, 21, 22, 23, 24, 25, 26, 29, 32, 33, 35, 36, 38, 39, 40, 42, 44, 48, 50, 52, 54, 56, 58, 59, 61, 62, 64, 66, 67, 69, 70, 71, 72, 73, 74, 77, 79, 80, 82, 84],
# [0,1,2,3,4,5,7,9,11,13,14,15,17,19,21,23,25,27,29,31,33,35,37,39,42,43,45,47,49,51,52,53,55,57,59,61,63,65,66,67,68,69,71,72,74,75,77,80,82,84,86,88,90,91,92,93,94,96,98,100,101,102,104,108,109,115,117,119,123,124,127,129,131,132,134,135,137,138,140,141,143,144,146,147,149,150,152,153,155,156,158,159,161,162,164,166,169,172,173,175,177,180,181,182,184,185,187,189,191,194,198,200,202,204,207,209,212,213,214,216,218,219,221,223,225,228,231,233,237,238,239,240,241,242,243,244,245,249,250,251,252,253,254,255,256,257,259,261,263,265,266,267,269,270,271,272,273,276,279,281,284,286,289,],

# ][9:10]
# with open('Additional Statistics/project-domains.txt', 'w+') as f:
#     myTable = PrettyTable(["Domain", "Projects"])
#     myTable.add_row(["Game", "adventure, seagull"])
#     myTable.add_row(["IC", "icemu"])
#     myTable.add_row(["Programming Language", "imp"])
#     myTable.add_row(["Network", "scion"])
#     myTable.add_row(["Smart Contract", "tinychain"])
#     myTable.add_row(["Data Science", "relex"])
#     myTable.add_row(["Web", "htmlark"])
#     myTable.add_row(["Datetime", "pendulum"])
#     f.write(str(myTable))
# special types like any, none and callable are sensitive
check_ret = True
ignore_no_res = False
ignore_ground_no_return = False

all_precisions = 0
all_recalls = 0
all_f1s = 0
all_cnt = 0
mrrs = 0
no_match_ground = []


  
not_report = ['TypeVarExpr', 'TempNode'] 

cate_times = defaultdict(dict)
cates = set()
for ii, project in enumerate(projects):
   
    t1 = 0
    t2 = 0
    f = f'results/lexical_stat-{project}'
    with open(f) as f:
        
        for i, line in enumerate(f):
            line = line.strip()
            cate, times =  line.split(':')
            cate = cate[22:-2]
            if cate not in not_report:
                cates.add(cate)
                cate_times[project][cate] = int(times)


def sum_cate(cate):
    s = 0
    for project in projects:
        if cate not in cate_times[project]:
            pass
        else:
            s += cate_times[project][cate]
    return s
cates = list(cates)
expr_cates = [x for x in cates if (x.find('Expr') != -1 or x.find('Comprehension')!=-1) and x.find('Stmt')==-1]
expr_cates = sorted(expr_cates, key = lambda x: sum_cate(x), reverse=True)

stmt_cates = [x for x in cates if x.find('Block') != -1 or x.find('Stmt') != -1 or x .find('Def') != -1 or x.find('Import') != -1 or x.find('Decl')!=-1]
stmt_cates = sorted(stmt_cates, key = lambda x: sum_cate(x), reverse=True)

tot = 0 
higher_than_5 = 0
for cate in expr_cates:
    s = sum_cate(cate)
    tot += s
    if s >= 5:
        higher_than_5 += 1
    else:
        print(cate)
print('avg:' + str(tot/len(expr_cates)))
print('med:' + str(sum_cate(expr_cates[int(len(expr_cates)/2)])))
print('ht5:' + str(higher_than_5))


tot = 0 
higher_than_5 = 0
for cate in stmt_cates:
    s = sum_cate(cate)
    tot += s
    if s >= 5:
        higher_than_5 += 1
    else:
        print(cate)
print('avg:' + str(tot/len(stmt_cates)))
print('med:' + str(sum_cate(expr_cates[int(len(stmt_cates)/2)])))
print('ht5:' + str(higher_than_5))

with open('Additional Statistics/expr_stat.txt', 'w+') as f:
    myTable = PrettyTable(['Project'] + expr_cates)
    for project in projects:
        row = [project]
        for cate in expr_cates:
            if cate not in cate_times[project]:
                row.append('0')
            else:
                row.append(str(cate_times[project][cate]))
        myTable.add_row(row)

    f.write(str(myTable))

with open('Additional Statistics/stmt_stat.txt', 'w+') as f:
    myTable = PrettyTable(['Project'] + stmt_cates)
    for project in projects:
        row = [project]
        for cate in stmt_cates:
            if cate not in cate_times[project]:
                row.append('0')
            else:
                row.append(str(cate_times[project][cate]))
        myTable.add_row(row)

    f.write(str(myTable))
