import csv
import time
import random

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
from sklearn import metrics

from graphs import graphs
from data.data import Data

def write_to_csv(fvs, header, csv_path):
    with open(csv_path, 'w') as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerow(header)
        writer.writerows(fv for fv in fvs)

def read_from_csv(csv_path):
    with open(csv_path, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        l = list(reader)
        for row in l[1:]:
            for i, col in enumerate(row[1:]):
        #        #row[col] = int(row[col])
                row[i+1] = int(col)
        return l

def train(data):
    fvs, labels = zip(*data)
    X_train = [fv[1:] for fv in fvs] # remove path from feature vector
    y_train = labels

    clf = RandomForestClassifier(n_estimators=100)

    param_grid = {
        'n_estimators': [5, 10, 15, 20],
        'max_depth': [2, 5, 7, 9]
    }
    from sklearn.model_selection import GridSearchCV
    clf = GridSearchCV(clf, param_grid, cv=10)
    clf.fit(X_train, y_train)
    clf = clf.best_estimator_

    return clf

if __name__ == '__main__':
    feature_names = read_from_csv('../data/evasive_benign.csv')[0][1:]

    # Load data sources
    evasive_b = read_from_csv('../data/evasive_benign.csv')[1:]
    evasive_m = read_from_csv('../data/evasive_malicious.csv')[1:]
    contagio_b = read_from_csv('../data/contagio_benign.csv')[1:]
    contagio_m = read_from_csv('../data/contagio_malicious.csv')[1:]
    virusshare_m = read_from_csv('../data/virusshare.csv')[1:]

    # Make data sets
    standard_data = Data(contagio_b[:3000],
                    contagio_m[:2500] + virusshare_m[:500]) 
    evasive_data = Data(evasive_b[:3000], evasive_m[:3000]) 
    mixed_data = Data([], [])
    mixed_data.tt = standard_data.tt + evasive_data.tt
    mixed_data.eval = standard_data.eval + evasive_data.eval

    random.shuffle(mixed_data.tt)
    random.shuffle(mixed_data.eval)

    half = len(mixed_data.tt) // 2
    mixed_data.tt = mixed_data.tt[:half]
    mixed_data.eval = mixed_data.eval[:half]

    # Make models
    standard_model = ("Standard", train(standard_data.tt))
    evasive_model = ("Evasive", train(evasive_data.tt))
    mixed_model = ("Mixed", train(mixed_data.tt))
    models = [standard_model, evasive_model, mixed_model]

    #########################################
    #                                       # 
    # Feature importance                    #
    #                                       #
    #########################################

    print("STANDARD IMPORTANCE!")
    graphs.generate_feature_importance(standard_model, feature_names)

    print("EVASIVE IMPORTANCE!")
    graphs.generate_feature_importance(evasive_model, feature_names)

    print("MIXED IMPORTANCE!")
    graphs.generate_feature_importance(mixed_model, feature_names)

    #########################################
    #                                       # 
    # Evasion sample predictions            #
    #                                       #
    #########################################

    ev = read_from_csv('../evasion_pdfs/evasion_sample.csv')[1:]
    graphs.generate_evasion_sample_predictions(models, ev, "1")

    ev = read_from_csv('../evasion_pdfs/evasion_sample_revs.csv')[1:]
    graphs.generate_evasion_sample_predictions(models, ev, "2")

    #ev2 = evasive_m[:30]
    #graphs.generate_evasion_sample_predictions(models, ev2)

    #########################################
    #                                       # 
    # Detector metrics tables               #
    #                                       #
    #########################################

    print("STANDARD DATA")
    graphs.generate_detector_metrics(models, standard_data.eval, "standard")
    print("EVASIVE DATA")
    graphs.generate_detector_metrics(models, evasive_data.eval, "evasive")
    print("MIXED DATA")
    graphs.generate_detector_metrics(models, mixed_data.eval, "mixed")

    #########################################
    #                                       # 
    # Prediction probability distributions  #
    #                                       #
    #########################################

    # STANDARD MODEL, STANDARD DATA
    graphs.generate_score_distribution_graph(standard_model, standard_data.eval, "Standard Model, Standard Data")
    # STANDARD MODEL, EVASIVE DATA
    graphs.generate_score_distribution_graph(standard_model, evasive_data.eval, "Standard Model, Evasive Data")
    # STANDARD MODEL, MIXED DATA
    graphs.generate_score_distribution_graph(standard_model, mixed_data.eval, "Standard Model, Mixed Data")

    # EVASIVE MODEL, STANDARD DATA
    graphs.generate_score_distribution_graph(evasive_model, standard_data.eval, "Evasive Model, Standard Data")
    # EVASIVE MODEL, EVASIVE DATA
    graphs.generate_score_distribution_graph(evasive_model, evasive_data.eval, "Evasive Model, Evasive Data")
    # EVASIVE MODEL, MIXED DATA
    graphs.generate_score_distribution_graph(evasive_model, mixed_data.eval, "Evasive Model, Mixed Data")

    # MIXED MODEL, STANDARD DATA
    graphs.generate_score_distribution_graph(mixed_model, standard_data.eval, "Mixed Model, Standard Data")
    # MIXED MODEL, EVASIVE DATA
    graphs.generate_score_distribution_graph(mixed_model, evasive_data.eval, "Mixed Model, Evasive Data")
    # MIXED MODEL, MIXED DATA
    graphs.generate_score_distribution_graph(mixed_model, mixed_data.eval, "Mixed Model, Mixed Data")
