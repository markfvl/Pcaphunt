import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score, f1_score, accuracy_score, precision_score, recall_score
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential, load_model, Model
from tensorflow.keras.layers import Dense, Dropout, Embedding, LSTM, concatenate, Input
from tensorflow.keras.metrics import Recall, Precision, AUC
from tensorflow.keras.preprocessing.text import Tokenizer
from sklearn.feature_extraction import DictVectorizer
import joblib

from . import dgautil as util


def train(dataset, save_path, model_name, epoches = 10):

    print(f"Preparing the model: {model_name}")
    df = pd.read_csv(dataset)

    X_text = df['SLD']
    X_entropy = df['Entropy']
    X_sld_length = df['SLD length']
    X_domain_length = df['Domain length']
    X_ttl = df['TTL']
    X_age = df['Age']
    y = df['DGA']

    X_text = X_text.astype(str)

    X_text_train, X_text_test, X_entropy_train, X_entropy_test, X_sld_length_train, X_sld_length_test, X_domain_length_train, X_domain_length_test, X_ttl_train, X_ttl_test, X_age_train, X_age_test, y_train, y_test = train_test_split(
        X_text, X_entropy, X_sld_length, X_domain_length, X_ttl, X_age, y, test_size=0.2, random_state=42)

    tokenizer = Tokenizer()
    tokenizer.fit_on_texts(X_text_train)

    # Convert domain names to sequences of integers
    X_text_train_seq = tokenizer.texts_to_sequences(X_text_train)
    X_text_test_seq = tokenizer.texts_to_sequences(X_text_test)

    # Pad sequences to a maximum length
    max_length = max(len(seq) for seq in X_text_train_seq)
    X_text_train_padded = pad_sequences(X_text_train_seq, maxlen=max_length)
    X_text_test_padded = pad_sequences(X_text_test_seq, maxlen=max_length)

    # Convert additional features to NumPy arrays
    X_train_additional = np.column_stack((X_entropy_train, X_sld_length_train, X_domain_length_train, X_ttl_train, X_age_train))
    X_test_additional = np.column_stack((X_entropy_test, X_sld_length_test, X_domain_length_test, X_ttl_test, X_age_test))

    vocab_size = len(tokenizer.word_index) + 1

    print(f"Build {model_name}")
    input_text = Input(shape=(max_length,), dtype="int32")
    input_additional = Input(shape=(X_train_additional.shape[1],))

    embedding = Embedding(input_dim=vocab_size, output_dim=128)(input_text)
    lstm = LSTM(128)(embedding)
    dropout = Dropout(0.5)(lstm)
    concatenated = concatenate([dropout, input_additional])
    output = Dense(1, activation='sigmoid')(concatenated)

    model = Model(inputs=[input_text, input_additional], outputs=output)

    model.compile(loss='binary_crossentropy', optimizer='rmsprop', metrics=[Recall(), Precision(), AUC()])
    
    epoch_number = epoches
    batchSize = 128
    
    # Training the model
    model.fit(
        [X_text_train_padded, X_train_additional],
        y_train,
        validation_data =([X_text_test_padded, X_test_additional], y_test),
        epochs = epoch_number,
        batch_size = batchSize
    )  

    model_path = save_path + "/" + model_name + ".joblib"
    
    metadata = {
        'max_length': max_length
    }

    joblib.dump((model, metadata), model_path)

    # Evaluate the model
    y_pred = model.predict([X_text_test_padded, X_test_additional])
    y_pred_binary = np.round(y_pred).flatten()

    f1 = f1_score(y_test, y_pred_binary)
    roc_auc = roc_auc_score(y_test, y_pred)
    accuracy = accuracy_score(y_test, y_pred_binary)
    precision = precision_score(y_test, y_pred_binary)
    recall = recall_score(y_test, y_pred_binary)

    print(f"F1 Score: {f1:.4f}")
    print(f"ROC AUC Score: {roc_auc:.4f}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")

    return [model, metadata]


def load(load_path):
    model, metadata = joblib.load(load_path)
    return [model, metadata]


def predict_domain(domain, lstm, max_length, tokenizer):
    sld = util.extract_sld(domain)
    entropy = util.calculate_entropy(sld)
    ttl = util.get_domain_ttl(domain)
    age = util.get_domain_age(domain)    
    
    sld_seq = tokenizer.texts_to_sequences([sld])
    sld_padded = pad_sequences(sld_seq, maxlen=max_length)

    additional = np.column_stack((entropy, len(sld), len(domain), ttl, age))

    prediction = lstm.predict([sld_padded, additional])
    prediction = np.round(prediction).flatten()

    return int(prediction[0])


def dga_prediction(model, domains, metadata):
    max_length = metadata['max_length']
    tokenizer = Tokenizer()

    for domain in domains:
        prediction = predict_domain(domain, model, max_length, tokenizer)
        if prediction == 0:
            print(f"\t{domain} is not DGA")
        else:
            print(f"\t{domain} is DGA")
