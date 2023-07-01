from . import dgautil as util
from . import randomforest

def detection(domains, dataset = "./net/dga/dataset_sample.csv", epoch = 20, model_dir = "./net/dga/models"):
    
    model_path = model_dir + "/*.joblib"
    models = util.search_models(model_dir, model_path)
    
    if len(models) == 0:
        print("No trained models have been found.")
        user_answer = util.check_user_input()
        if user_answer == 'y':
            model = randomforest.train(dataset, model_dir, epoch)
        else:
            return
    else:
        #load the model
        model = randomforest.load(models[0])

    # pass the domains to the model for prediction
    filtered_domains = util.domains_filter(domains)
    randomforest.dga_prediction(model, filtered_domains)

    