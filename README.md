# mal-pdf-detection

Used for my thesis, WIP


The code is not the most flexible, or cleanest. But may be adjusted manually for the desired functionality.

`main.py` is used for feature extraction.
`train.py` is used for training and testing models
`data/data.py` contains a simple dataset class
`graphs/graphs.py` contains the graph generation code (and detector testing)


### To run:

Make sure all required python dependencies are installed (numpy, sklearn, etc).

The parsers directory should contain both the pdfid and peepdf PDF parsers, in their own directories:
```
parsers/
    - pdfid/
        -  pdfid.py
        -  ...
    - peepdf/
        -  peepdf.py
        -  ...
```
Fetch these from their sources.


In `main.py`, set the following:
- `csv_path`: path of the output csv-file which contains the extracted features for each supplied PDF file
- `pdf_dir`: path of directory from which PDF-files should be collected

Extract the features:
```bash
python3 main.py
```

In its current implementation `train.py` requires the existence of five csv:s:
- `data/evasive_benign.csv`
- `data/evasive_malicious.csv`
- `data/contagio_benign.csv`
- `data/contagio_malicious.csv`
- `data/virusshare.csv`

These are used to construct the three datasets:
- `standard`
- `evasive`
- `mixed`

See the thesis report for more information.

Once these have been generated using the feature extraction steps above, perform the training and testing with:

```bash
python3 test.py
```
