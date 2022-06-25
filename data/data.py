import random

class Data:
    def __init__(self, benign, malicious):
        fvs = benign + malicious
        labels = [0] * len(benign) + [1] * len(malicious)
        data = list(zip(fvs, labels))

        # mix samples of varying sources and recency
        random.seed(4)
        random.shuffle(data)

        # split data into Train&Test and Evaluation data sets
        half = len(data) // 2
        self.tt, self.eval = data[:half], data[half:]
