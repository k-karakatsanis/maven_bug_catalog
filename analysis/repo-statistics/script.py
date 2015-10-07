import xlrd
 
#----------------------------------------------------------------------
def open_file(path):
    book = xlrd.open_workbook(path)
    sheet_names = ('sql', 'xss', 'hrs')
    sheets = []
    projects = []
    jars = []

    for name in sheet_names:
        sheets.append(book.sheet_by_name(name))

    for sheet in sheets:
        for row in range(2, sheet.nrows):
            if any(sheet.cell(row, col).value == 1 for col in range(5, 7)):
                projects.append(sheet.cell(row, 0).value.encode('utf-8'))
                jars.append(sheet.cell(row, 1).value.encode('utf-8'))

    print("projects = {}".format(projects))
    print("")
    print("jars = {}".format(jars))
 
#----------------------------------------------------------------------
if __name__ == "__main__":
    path = "Security Bugs (jars).xlsx"
    open_file(path)
