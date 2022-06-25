from parsers.pdfid import pdfid

import csv
import time
import json
import subprocess

import os
from os import listdir
from os.path import isfile, join, basename

def write_to_csv(fvs, header, csv_path):
    with open(csv_path, 'w') as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerow(header)
        writer.writerows(fv for fv in fvs)

def read_from_csv(csv_path):
    with open(csv_path, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        return list(reader)

def pdfid_2_json(path, writedir=None):
    xmldoc = pdfid.PDFiD(path)
    force = False
    data = pdfid.PDFiD2JSON(xmldoc, force)

    if writedir:
        out_path = join(writedir, basename(path))[:-4] + '.pdfid'
        with open(out_path, "w+") as f:
            f.write(data)

    data = json.loads(data)
    return data

def peepdf_2_json(path, writedir=None):
    out = subprocess.getoutput("python parsers/peepdf/peepdf.py -m -j -f '" + path + "'")

    if writedir:
        out_path = join(writedir, basename(path))[:-4] + '.peepdf'
        with open(out_path, "w+") as f:
            f.write(out)

    data = json.loads(out)
    return data

def extract_features(path):
    # extract pdfid data
    try:
        data = pdfid_2_json(path, writedir=raw_dir)
    except:
        print(f"ERROR, pdfid2json for file {path}")
        return None

    # collect keyword counts
    keywords = {}
    for kw in data[0]['pdfid']['keywords']['keyword']:
        keywords[kw['name']] = kw['count'] + kw['hexcodecount']

    # select pdfid features
    pdfid_fv = [('endobj', keywords['endobj']),
                ('/JS', keywords['/JS']),
                ('/JavaScript', keywords['/JavaScript']),
                ('startxref', keywords['startxref']),
                ('/Page', keywords['/Page']),
                ('xref', keywords['xref'])]

    # extract peepdf data
    try:
        data = peepdf_2_json(path, writedir=raw_dir)['peepdf_analysis']
    except:
        print(f"ERROR, peepdf2json for file {path}")
        return None
    basic = data['basic']
    advanced = data['advanced'][0]['version_info']

    # select peepdf features
    f_actions_dict = advanced['suspicious_elements']['actions']
    f_actions = sum([len(action) for action in f_actions_dict.values()]) if f_actions_dict else 0
    f_triggers_dict = advanced['suspicious_elements']['triggers']
    f_triggers = sum([len(trigger) for trigger in f_triggers_dict.values()]) if f_triggers_dict else 0
    peepdf_fv = [('Updates', basic['updates']),
                 ('encoded_streams', len(advanced['encoded_streams'])),
                 ('Actions', f_actions),
                 ('Triggers', f_triggers),
                 ('Size', basic['size'])]

    # select 'shared' features (from peepdf)
    shared_fv = [('obj', basic['num_objects']),
                 ('stream', basic['num_streams'])]

    # derived feature
    obj_count = keywords['obj']
    sus_count = (keywords['/JavaScript']
                 + keywords['/OpenAction']
                 + keywords['/AA']
                 + keywords['/Launch']
                 + keywords['/EmbeddedFile'])
    little_content = int(obj_count < 25 and sus_count >= 2)
    derived_fv = [('little_content', little_content)]

    fv = [('path', path)] + pdfid_fv + peepdf_fv + shared_fv + derived_fv
    return fv

if __name__ == '__main__':
    csv_path = 'output/output.csv'
    pdf_dir = '.'
    files = [join(pdf_dir, f) for f in listdir(pdf_dir) if isfile(join(pdf_dir, f)) and f.endswith('.pdf')]
    print(*files)


    raw_dir = 'output/raw'
    if not os.path.exists(raw_dir):
        os.makedirs(raw_dir)
    error_dir = 'output/errors'
    if not os.path.exists(error_dir):
        os.makedirs(error_dir)

    header = []
    fvs = []
    write = True
    for f in files:
        print(f'Extracting {f}')
        fv = extract_features(f)

        # record errors to file
        if not fv:
            with open(join(error_dir, 'errors.txt'), 'a+') as errf:
                errf.write('Error parsing ' + f)
            continue

        header = [name for name, count in fv]
        fv = [count for name, count in fv]
        fvs.append(fv)

    if write:
        write_to_csv(fvs, header, csv_path)

