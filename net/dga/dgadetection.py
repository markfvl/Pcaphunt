import pyshark

from . import dgautil as util
from . import randomforest as rf
from . import lstm

import nest_asyncio
nest_asyncio.apply()

def detection(domains, type = "rfc", dataset = "./net/dga/dataset_sample.csv", epoch_num = 20, save_dir = "./net/dga/models", load_dir = ".net/dga/models", model_name = None):
    
    default_name = "random_forest" if type == "rfc" else "lstm"
    default_dir = "./net/dga/models"
    models = []

    if load_dir != default_dir:
        '''if model_name != None:
            model_path = load_dir + f"/{model_name}.joblib"
        else:
            model_path = load_dir + "/*.joblib"'''
        model_path = load_dir + "/*.joblib"
        models = util.search_models(load_dir, model_path)
    else:
        '''if model_name != None:
            model_path = save_dir + f"/{model_name}.joblib"
        else:
            model_path = save_dir + "/*.joblib"'''
        model_path = save_dir + "/*.joblib"
        models = util.search_models(save_dir, model_path)
    
    if len(models) == 0:
        print("No trained models have been found.")
        user_answer = util.check_user_input()
        if user_answer == 'y':
            model_name = default_name if model_name == None else model_name
            if type == "rfc":
                load_model = rf.train(dataset, save_dir, model_name, epoch_num)
            else:
                train_data = lstm.train(dataset, save_dir, model_name, epoch_num)
                load_model = train_data[0]
                load_model_metadata = train_data[1]
        else:
            return
    else:
        model_found = False
        for model in models:
            if model_name in model:
                if type == "rfc":
                    load_model = rf.load(model)
                else:
                    load_data = lstm.load(model)
                    load_model = load_data[0]
                    load_model_metadata = load_data[1]
                model_found = True

        if not model_found: # train the model
            if type == "rfc":
                load_model = rf.train(dataset, save_dir, model_name, epoch_num)
            else:
                train_data = lstm.train(dataset, save_dir, model_name, epoch_num)
                load_model = train_data[0]
                load_model_metadata = train_data[1]

    # give the domains to the model for prediction
    filtered_domains = util.domains_filter(domains)
    name_of_model = default_name if model_name == None else model_name
    print(f"DGA prediction by {name_of_model} :")
    if type == "rfc":
        rf.dga_prediction(load_model, filtered_domains)
    else:
        lstm.dga_prediction(load_model, filtered_domains, load_model_metadata)
    print()


def detection_pcap(filePath, type = "rfc", dataset = "./net/dga/dataset_sample.csv", epoch_num = 20, save_dir = "./net/dga/models", load_dir = ".net/dga/models", model_name = None):

    filter = "dns and dns.flags == 0x0100"
    cap = pyshark.FileCapture(filePath, display_filter = filter)
    domains = []

    for pkt in cap:
        domains.append(pkt.dns.qry_name)
        
    detection(domains, type, dataset, epoch_num, save_dir, load_dir, model_name)
    
    
def detection_txt(txtFile, type = "rfc", dataset = "./net/dga/dataset_sample.csv", epoch_num = 20, save_dir = "./net/dga/models", load_dir = ".net/dga/models", model_name = None):
    domains = []
    try:
        with open(txtFile, 'r') as file:
            for line in file:
                line = line.strip()
                domains.append(line)
    finally:
        file.close()
    
    detection(domains, type, dataset, epoch_num, save_dir, load_dir, model_name)