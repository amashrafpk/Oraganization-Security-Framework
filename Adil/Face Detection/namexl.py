import xlwt;
from datetime import datetime;
from xlrd import open_workbook;
from xlwt import Workbook;
from xlutils.copy import copy
from pathlib import Path

def output(filename, sheet,num,id, name):
    my_file = Path('C:\\Users\\Adil\\PycharmProjects\\SE\\attendance\\firebase\\attendance_files\\'+filename+'.xls')
    if my_file.is_file():
        rb = open_workbook('C:\\Users\\Adil\\PycharmProjects\\SE\\attendance\\firebase\\attendance_files\\'+filename+'.xls')
        book = copy(rb)
        sh = book.get_sheet(0)
        # file exists
    else:
        book = xlwt.Workbook()
        sh = book.add_sheet(sheet)
    style0 = xlwt.easyxf('font: name Times New Roman, color-index red, bold on',num_format_str='#,##0.00')
    style1 = xlwt.easyxf(num_format_str='D-MMM-YY')

    #variables = [x, y, z]
    #x_desc = 'Display'
    #y_desc = 'Dominance'
    #z_desc = 'Test'
    #desc = [x_desc, y_desc, z_desc]


    col1_name = 'id'
    col2_name = 'name'


    sh.write(0,0,col1_name,style0);
    sh.write(0, 1, col2_name,style0);

    sh.write(num+1,0,id);
    sh.write(num+1, 1, name);
    #You may need to group the variables together
    #for n, (v_desc, v) in enumerate(zip(desc, variables)):
    fullname=filename+'.xls';
    book.save('C:\\Users\\Adil\\PycharmProjects\\SE\\attendance\\firebase\\attendance_files\\'+fullname)
    return fullname;
