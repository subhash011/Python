# Malware Detector
To run the detector use the command 
python3 MalwareDetection.py directory_name
where directory_name is the name of the directory with test files
The output will be available as output.csv in the same directory.

# Test Structure
- directory_name
   - hash of folder (static)
        - string.txt
        - structure_info.txt
   - hash of json (dynamic)
     
    _Note: Static and Dynamic can be in any order. 
    The above structure must be followed_

# Libraries used:
```
pandas
os
csv
random
pickle
argparse
numpy
seaborn
requests
shutil
statistics
sklearn
time
ast
```

# Dataset:
The Features directory contains datasets for both static and dynamic analysis as pickle files which stores pandas dataframes.
## dynamic directory:
   Contains test data(pandas dataframe), test labels(numpy array), train data for benigns(pandas dataframe), train data foor malwares(pandas dataframe)
## static directory:
   Contains test data(pandas dataframe), test labels(numpy array), train data for benigns(pandas dataframe), train data foor malwares(pandas dataframe)
## models:
   contains models built for static and dynamic analysis respectively. The models are RandomForestClassifiers from sklearn.
