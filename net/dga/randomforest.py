import pandas as pd
import ast
from tqdm import tqdm
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, f1_score, roc_auc_score

from . import dgautil as util


def train(dataset, save_path, model_name, estimators = 20):

    print(f"Preparing the model: {model_name}")
    df = pd.read_csv(dataset)

    #converting the 'Character Distribution' column from string to dictionary
    df['Character Distribution'] = df['Character Distribution'].apply(ast.literal_eval)

    X = df[['SLD', 'Entropy', 'Character Distribution', 'SLD length', 'Domain length', 'TTL', 'Age']]
    y = df['DGA']

    if y.isnull().any():
        raise ValueError("Target variable contains missing values")

    # converting the 'Character Distribution' column into binary features 
    mlb = MultiLabelBinarizer()
    char_dist_encoded = pd.DataFrame(mlb.fit_transform(X['Character Distribution']), columns=mlb.classes_)

    X_encoded = pd.concat([char_dist_encoded, X[['Entropy', 'SLD length', 'Domain length', 'TTL', 'Age']]], axis=1)

    # Splitting the data
    X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.2, random_state=42)

    # Create and train the Random Forest classifier
    print(f"Training {model_name}:")
    classifier = RandomForestClassifier(n_estimators=estimators, random_state=42, n_jobs=-1)
    for i in tqdm(range(estimators)):
        classifier.set_params(n_estimators=i + 1)
        classifier.fit(X_train, y_train)

    print(f"Saving the model in {save_path}")
    model_path = save_path + "/" + model_name + ".joblib"
    joblib.dump(classifier, model_path)

    # Predictions on the test set and model evaluation metrics
    print("\nModel statistics:")
    predictions = classifier.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    print(f"\tAccuracy: {accuracy}")

    recall = recall_score(y_test, predictions)
    print(f"\tRecall: {recall}")

    f1 = f1_score(y_test, predictions)
    print(f"\tF1 Score: {f1}")

    probabilities = classifier.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, probabilities)
    print(f"\tAUC: {auc}")
    print()

    return classifier


def load(load_path):
    return joblib.load(load_path)
    

def predict_domain(domain, classifier):
    sld = util.extract_sld(domain)
    entropy = util.calculate_entropy(sld)
    char_dist = util.calculate_char_distribution(sld)
    char_dist = pd.DataFrame([char_dist])
    ttl = util.get_domain_ttl(domain)
    age = util.get_domain_age(domain)
    
    input_data = pd.DataFrame(columns=classifier.feature_names_in_)
    input_data.loc[0] = 0
    input_data['Entropy'] = entropy
    input_data['SLD length'] = len(sld)
    input_data['Domain length'] = len(domain)
    input_data['TTL'] = ttl
    input_data['Age'] = age
    input_data[char_dist.columns] = char_dist

    prediction = classifier.predict(input_data)
    return prediction[0]


def dga_prediction(classifier, domains):
    for domain in domains:
        prediction = predict_domain(domain, classifier)
        if prediction == 0:
            print(f"\t{domain} is not DGA")
        else:
            print(f"\t{domain} is DGA")
