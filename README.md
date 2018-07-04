# HTTPSDetectorTool
Python tool to detect https malware 
traffic with machine learning techniques.


## ****Installation****
Tested on (Ubuntu 16.04 x64) and (Kali 2017.1 x64) 

Clone the repository:
```
git clone https://github.com/frenky-strasak/HTTPSDetectorTool.git --recursive
```

Create new environment (for exmaple conda):
```
conda create --name py36HTTPSDetectorTool python=3.6
```

Activate the environment:
```
source activate py36HTTPSDetectorTool
```
Go to the project directory:
```
cd HTTPSDetectorTool
```
Install required dependencies:
```
pip install -r requirements.txt
```
Run the program:
```
python main.py --help 
```

## 
Time format

If your bro data has started time of the capturing from 0 (it means from 1 January 1970), please put text file 
with name "start_date.txt" one level directory higher. Example:
```
/home/data/my_capture/bro/con.log
/home/data/my_capture/start_date.txt
```
The file will contain one number in one line representing date in unix time.