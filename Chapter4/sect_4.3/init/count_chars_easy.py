import sys
import random

if __name__ == '__main__':

    file_to_analyze = sys.argv[1]
    outputfile = sys.argv[2]

    best_outputfile = outputfile + "_best"
    worst_outputfile = outputfile + "_worst"
    random_outputfile = outputfile + "_random"

    inputtext = open(file_to_analyze,'r').read()
    resultset = dict.fromkeys(inputtext,0)

    for char in inputtext:
        resultset[char] += 1
    print(resultset)


    best_result = sorted(resultset, key=resultset.get, reverse=True)
    worst_result = sorted(resultset, key=resultset.get, reverse=False)



    out = open(best_outputfile, 'w+')
    for char in best_result:
        out.write(char + '\n')
    out.close()

    out = open(worst_outputfile, 'w+')
    for char in worst_result:
        out.write(char + '\n')
    out.close()


    lines = open(best_outputfile, 'r').readlines()
    random.shuffle(lines)
    open(random_outputfile, 'w+').writelines(lines)
