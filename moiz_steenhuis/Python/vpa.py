import csv

# Reads fileList.csv
fileList = {}
with open('/home/moiz_steenhuis/Log/fileList.csv', 'r') as file:
    reader = csv.DictReader(file)
    for row in reader:
        fileList[row['Files']] = float(row['Weight'])

# Reads assess.csv and siem.csv, creats prior.csv
priorData = []
with open('/home/moiz_steenhuis/Log/assess.csv', 'r') as assessFile, open('/home/moiz_steenhuis/Log/siem.csv', 'r') as siemFile, open('/home/moiz_steenhuis/Log/prior.csv', 'w', newline='') as priorFile:
    assessReader = csv.DictReader(assessFile) #Row 12 extends out of the image, but it does open all of the csv files
    siemReader = csv.DictReader(siemFile)
    priorWriter = csv.DictWriter(priorFile, fieldnames=['Location', 'Weight', 'Vulnerability'])
    priorWriter.writeheader()

    for row in assessReader:
        priorData.append(row)
        priorWriter.writerow(row)

    for row in siemReader:
        priorData.append(row)
        priorWriter.writerow(row)
#prior.csv now contains both the siem and assess csv files

# Update weight values in prior.csv
for row in priorData:
    file = row['Location']
    if file in fileList:
        # the prior weight value is the product of the fileList's weight value and the vulnerability/event weight
        row['Weight'] = str(float(row['Weight']) * fileList[file])

# So glad that python has a built-in sort function (looking at you Java)
priorData.sort(key=lambda x: float(x['Weight']), reverse=True)

# Print the top 5 rows with the highest weight values, those are the vulnerabilities that the user must fix as soon as possible
print("Top 5 Weight Values:")
for row in priorData[:5]:
    print(row)

