# SimpleFirewall
A simple firewall model that filters packets based on direction, protocol, port and ip address

## Description:
I implemented the Firewall class in "firewall.py", and also wrote a unit test file in "firewall_test.py". Note that the unittest would
load the file "fw.csv" as the dataset.

To run the unit test, just type
```
python -m unittest firewall_test.py
```
To test the performance, I also create another file "create_data_and_test.py", which randomly create 1M rules. Then it loads the data with firewall and then run query test. After loading and processing the dataset, it works quickly. In my PC, the loading time is 10s, and the average query time is less than 0.05ms.

To test the performance, just type
```
python create_data_and_test.py
```
## Discussion:
### My approach:
A naive solution is to store all rules as a table. For each query, we just iterate through it to check whether it matches.
My approach is simple and similar. I store all port and ip ranges of the same direction and protocol in a list, so there are 4 lists.
Both time and space complexity is O(N). Although the time complexity is still O(N), if the data distribution is somewhat uniform, the query time can be a quarter of the original one.

### Better approach:
1. We can easily come up with O(1) time solution for each query. That is create and query a 2D table for ports and ip ranges. For the corresponding rule, we just fill all entries as 1. However, it's impracticable since it requires a lot of space (2**32)*(65536), and the initialization time is also intractable.
2. Another method I tried is to create a list of port legnth 65536. Each port map to a list of sorted and processed ip ranges. Then, for a given query, I first use the port number to find the sorted ip list and perform binary search to find the ip address. Time complexity is
O(logN). However, the performance of this method is not good since the space O(65536)*O(N) may still be a problem when N becomes 1 million.
3. The final method may be interval tree. We can use ip address as interval, and port as the associated data. Then, for each query, we first find all the associated ip intervals and check all the corresponding ports. It's still O(N), but search space is much smaller.

## Teams that I'm interested in:
1. Platform team
2. Data team
3. Policy team

I'm especially interested in platform team since I would like to know
how to design a great system that can scale out and deal with the large 
amount of data. I also want to contribute my knowledge and experience in
software development to this team.
Data team sounds also great to me. Since I have experience in Machine Learning,
building data pipeline and data visualization are also interestring to me.
