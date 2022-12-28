import sys
import numpy





if __name__ == '__main__':

    file_to_analyze = sys.argv[1]
    outputfile = sys.argv[2]

    best_outputfile = outputfile + "_best"
    worst_outputfile = outputfile + "_worst"

    inputtext = open(file_to_analyze, 'r').read()
    character_array = numpy.chararray(100)
    counting_array = numpy.full(shape=100, fill_value=0,dtype=numpy.int)
    for character_inputtext in inputtext:
        counter = 0
        for character_known in character_array:
            #print(character)
            #print(char)
            #print(counter)
            #print(counting_array[counter])
            if character_inputtext == character_known:
                counting_array[counter] = counting_array[counter] + 1
                #print("known")
            elif character_known == '':
                character_array[counter] = character_inputtext
                counting_array[counter] = 1
                #print("new")
                break
            counter = counter + 1
            #if counter == len(character_array):
            #    break

        #if hit != 1:
        #    character_array[counter] = char
        #    counting_array[counter] = 1



    out = open(best_outputfile, 'w+')
    reverse_char_array = character_array[::-1]
    print(character_array)
    print(counting_array)
    #for char in character_array:
    #    string = str(char)
    #    out.write(string)
    #out.close()

    #out = open(worst_outputfile, 'w+')
    #for char in reverse_char_array:
    #    string = str(char)
    #    out.write(string)
    #out.close()


