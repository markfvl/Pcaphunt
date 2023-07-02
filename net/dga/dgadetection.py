import pyshark

from . import dgautil as util
from . import randomforest

import nest_asyncio
nest_asyncio.apply()

def detection(domains, dataset = "./net/dga/dataset_sample.csv", epoch_num = 20, save_dir = "./net/dga/models", load_dir = ".net/dga/models", model_name = None):
    
    default_name = "random_forest"
    default_dir = "./net/dga/models"
    models = []

    if load_dir != default_dir:
        if model_name != None:
            model_path = model_path = load_dir + f"/{model_name}.joblib"
        else:
            model_path = load_dir + "/*.joblib"
        models = util.search_models(load_dir, model_path)
    else:
        model_path = save_dir + "/*.joblib"
        models = util.search_models(save_dir, model_path)
    
    if len(models) == 0:
        print("No trained models have been found.")
        user_answer = util.check_user_input()
        if user_answer == 'y':
            model_name = default_name if model_name == None else model_name
            load_model = randomforest.train(dataset, save_dir, model_name, epoch_num)
        else:
            return
    else:
        model_found = False
        for model in models:
            if model_name in model:
                load_model = randomforest.load(model)
                model_found = True

        if not model_found: #train the model
            load_model = randomforest.train(dataset, save_dir, model_name, epoch_num)

    # give the domains to the model for prediction
    filtered_domains = util.domains_filter(domains)
    name_of_model = default_name if model_name == None else model_name
    print(f"DGA prediction by {name_of_model} :")
    randomforest.dga_prediction(load_model, filtered_domains)
    print()


def detection_pcap(filePath, dataset = "./net/dga/dataset_sample.csv", epoch_num = 20, save_dir = "./net/dga/models", load_dir = ".net/dga/models", model_name = None):

    filter = "dns and dns.flags == 0x0100"
    cap = pyshark.FileCapture(filePath, display_filter = filter)
    domains = []

    for pkt in cap:
        domains.append(pkt.dns.qry_name)
        
    detection(domains, dataset, epoch_num, save_dir, load_dir, model_name)
    
    
def detection_txt(txtFile, dataset = "./net/dga/dataset_sample.csv", epoch_num = 20, save_dir = "./net/dga/models", load_dir = ".net/dga/models", model_name = None):
    domains = []
    try:
        with open(txtFile, 'r') as file:
            for line in file:
                line = line.strip()
                domains.append(line)
    finally:
        file.close()
    
    detection(domains, dataset, epoch_num, save_dir, load_dir, model_name)
