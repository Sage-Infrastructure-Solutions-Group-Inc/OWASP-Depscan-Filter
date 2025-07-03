from argparse import ArgumentParser
import json
import csv

parser = ArgumentParser()
parser.add_argument('input_file', help='the depscan-universal.json file.')
parser.add_argument('output_file', help='the CSV file and path you would like to output to.')
parser.add_argument("--type", help='the package type you would like. (Default: npm)', default='npm')
parser.add_argument('--cvss-filter', help='the minimum severity you would like. (Default: 7)', default=7, type=float)

args = parser.parse_args()

csv_fields = ['id','package','purl','version','fix_version','severity','cvss_score']

filtered_data = []
with open(args.input_file) as json_file:
    # File is NDJSON formatted
    for line in json_file.readlines():
        data = json.loads(line)
        ptype = data.get('package_type')
        cvss = data.get('cvss_score')
        if cvss: cvss = float(cvss)
        if ptype == args.type and cvss and cvss >= args.cvss_filter:
            filtered_data.append(data)

with open(args.output_file, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_fields, extrasaction='ignore')
    writer.writeheader()
    for data in filtered_data:
        writer.writerow(data)

print('Finished filtered export.')

