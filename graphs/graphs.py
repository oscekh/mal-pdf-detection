from tabulate import tabulate
from sklearn import metrics
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages


def generate_feature_importance(model, feature_names):
    m_name, model = model
    imps = model.feature_importances_
    imps = sorted(list(zip(feature_names, imps)), key=lambda x: x[1], reverse=True)

    # make table
    tbl = tabulate(imps, headers=['Feature', 'Importance'])
    tbltex = tabulate(imps, headers=['Feature', 'Importance'], tablefmt='latex')
    print(tbl)
    print()

    # remove
    vals = [f[1] for f in imps]
    names = [f[0] for f in imps]

    # make graph
    plt.clf()
    fig = plt.figure()
    ax = fig.add_subplot(111)
    #ax.grid(linestyle=':')

    ax.barh(names, vals, align='edge', color='C4', edgecolor='black')
    #ax.hist(probs, bins=50, color='C4', edgecolor='black', linewidth=1.2)
    ax.set_xlabel('Importance', fontsize=13)
    ax.set_ylabel('Features', fontsize=13)
    ax.set_title(f'Feature importance in model: {m_name}')
    
    plt.tight_layout()
    plt.savefig(f'feature_importance_{m_name}.pdf', format='pdf')
    with open(f'feature_importance_{m_name}.txt', 'w+') as f:
        f.write(tbltex)

def generate_evasion_sample_predictions(models, samples, label):
    rows = [['Evasion Sample']]
    for s_path, *sample in samples:
        s_name = s_path.split('/')[-1]
        row = [s_name]
        for m_name, model in models:
            p_ben, p_mal = model.predict_proba([sample])[0]
            rows[0].append(m_name)
            row.append(p_mal)
        row.append(row[3]-row[1])
        rows.append(row)
    rows[0].append("Diff")
    diffs = [r[4] for r in rows[1:]]
    print(diffs)
    from scipy.stats import shapiro
    print(shapiro(diffs))

    tbl = tabulate(rows, headers='firstrow')
    tbltex = tabulate(rows, headers='firstrow', tablefmt='latex')
    print(tbl)
    print()
    with open(f'evasion_sample_predictions_{label}.txt', 'w+') as f:
        f.write(tbltex)

# Input
# - models: the random forest models (detectors) to be tested, of form [(modelname, scikit RF model)]
# - data: the data used to test the models, of form []
def generate_detector_metrics(models, data, data_name):
    data, labels = zip(*data)

    data = [d[1:] for d in data]
    rows = [['Detector', 'Accuracy', 'Precision', 'Recall', 'F1', 'TP', 'FP', 'TN', 'FN', 'Total']]
    for m_name, model in models:
        pred = model.predict(data)

        acc = metrics.accuracy_score(labels, pred)
        prec = metrics.precision_score(labels, pred)
        recall = metrics.recall_score(labels, pred)
        f1 = metrics.f1_score(labels, pred)

        # src: https://stackoverflow.com/a/31351145
        TP = 0
        FP = 0
        TN = 0
        FN = 0
        for i in range(len(pred)): 
            if labels[i] == pred[i] == 1:
               TP += 1
            if pred[i] == 1 and labels[i] != pred[i]:
               FP += 1
            if labels[i] == pred[i] == 0:
               TN += 1
            if pred[i] == 0 and labels[i] != pred[i]:
               FN += 1

        row = [m_name, acc, prec, recall, f1, TP, FP, TN, FN, len(pred)]
        rows.append(row)

    tbl = tabulate(rows, headers='firstrow')
    tbltex = tabulate(rows, headers='firstrow', tablefmt='latex')
    print(tbl)
    print()
    with open(f'detector_metrics_{data_name}.txt', 'w+') as f:
        f.write(tbltex)

def generate_score_distribution_graph(model, data, title):
    m_name, model = model
    probs_b = []
    probs_m = []
    for fv, label in data:
        prob = model.predict_proba([fv[1:]])[0][1]
        if label:
            probs_m.append(prob)
        else:
            probs_b.append(prob)
        
    print(f"Lengths of probs in {m_name} {title}")
    print(f"B: {len(probs_b)} M: {len(probs_m)}")
    
    plt.clf()
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.grid(linestyle=':')

    ax.hist(probs_b, bins=50, color='g', edgecolor='black', linewidth=1.2, label='Benign', log=True)
    ax.hist(probs_m, bins=50, color='r', edgecolor='black', linewidth=1.2, label='Malicious', log=True)
    #ax.hist(probs, bins=50, color='C4', edgecolor='black', linewidth=1.2)

    ax.set_xlabel('Maliciousness probability', fontsize=13)
    ax.set_ylabel('Sample Count', fontsize=13)
    ax.set_title(title)
    
    plt.legend()
    plt.tight_layout()
    #plt.show()
    title = title.lower().replace(',', '').replace(' ', '_')
    plt.savefig(f'score_distribution_{title}.pdf', format='pdf')
