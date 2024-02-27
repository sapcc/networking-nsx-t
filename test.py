import requests
import os
import json

from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError

user = f"{os.environ.get('OS_USERNAME')}"
password = os.environ.get('OS_PASSWORD')
bb = "bb271"
region = os.environ.get("OS_REGION_NAME")

url = f"https://nsx-ctl-{bb}.cc.{region}.cloud.sap"

infa = "policy/api/v1/infra/domains/default"

id = "02445586-8135-4e6b-9b76-120a03ca4ffc"

def get_session():
    session = requests.Session()
    session.auth = (user, password)
    return session
    
    
def put_group():
    session = get_session()
   
    dummy_group = {'id': id, 
                   'display_name': id, 
                   'path': f"/infra/domains/default/groups/{id}",
                   "_revision": 0,
                   'expression': [
                       {'value': f"security_group|{id}", 
                        'member_type': 'SegmentPort', 
                        'key': 'Tag', 
                        'operator': 'EQUALS', 
                        'resource_type': 'Condition'
                      }],
                    'tags': [{'scope': 'age', 'tag': 1705666590},
                             {'scope': 'revision_number', 'tag': 600}, 
                             {'scope': 'dummy', 'tag': "dummy"}]
                   }
    
    u = f"{url}/{infa}/groups/{id}"
    print(f"running put : {u}")
    try: 
        res = session.put(u, json=dummy_group)
    except (HTTPError, ConnectionError, ConnectTimeout) as err:
        print(err) 

    if res.ok:
        print("everything is fine")
    else:
        print("something went wrong")
        print(res)
        
def bulk():
    child_c = [
        {'resource_type': 'ChildGroup',
         'Group': {'id':  id, 'display_name': id,
                   'path': f'/infra/domains/default/groups/{id}', 'expression': [
                 {'value': f'security_group|{id}', 'member_type': 'SegmentPort',
                  'key': 'Tag', 'operator': 'EQUALS', 'resource_type': 'Condition'}],
                   'tags': [{'scope': 'age', 'tag': 1705662784}, {'scope': 'revision_number', 'tag': 200}],
                   '_revision': None, 'resource_type': 'Group'}},

        {'resource_type': 'ChildGroup',
         'Group': {'id': '05060e8a-a7f0-416c-a9aa-62d431c2d5e7', 'display_name': '05060e8a-a7f0-416c-a9aa-62d431c2d5e7',
                   'path': '/infra/domains/default/groups/05060e8a-a7f0-416c-a9aa-62d431c2d5e7', 'expression': [
                 {'value': 'security_group|05060e8a-a7f0-416c-a9aa-62d431c2d5e7', 'member_type': 'SegmentPort',
                  'key': 'Tag', 'operator': 'EQUALS', 'resource_type': 'Condition'}],
                   'tags': [{'scope': 'age', 'tag': 1705662784}, {'scope': 'revision_number', 'tag': 200}],
                   '_revision': None, 'resource_type': 'Group'}}
    ]
    container =  {"resource_type": "Infra",
            "children": [
                {
                    "resource_type": "ChildResourceReference",
                    "id": "default",
                    "target_type": "Domain",
                    "children": child_c
                }
            ]
    }

    session = get_session()

    u = f"{url}/policy/api/v1/infra"
    print(f"running patch: {u}")
    json_formatted_str = json.dumps(container, indent=4)
    print(json_formatted_str)
    try:
        res = session.patch(u, json=container)
    except (HTTPError, ConnectionError, ConnectTimeout) as err:
        print(err)
        print("something went wrong")
        exit(-1)

    if res.ok:
        print("everything is fine")
    else:
        print("something went wrong")
def get_revison_number():
    session = get_session()
  
    
    u = f"{url}/{infa}/groups/{id}" 
    print(f"running get: {u}")
    try:
        res = session.get(u)
    except (HTTPError, ConnectionError, ConnectTimeout) as err:
        print(err)
        print("something went wrong")
        exit(-1)
    
    if res.ok:
        print("everything is fine")
        json_formatted_str = json.dumps(res.json(), indent=4)
        print(json_formatted_str)
    else:
        print("something went wrong")
        print(res)

def search():
    port_id = "e8215be9-ebaa-4715-8eb8-71a3204391dc"
    SEARCH_DSL_QUERY =  {
        "query": f"resource_type: Group",
        "dsl": f"{port_id}",
        "data_source": "INTENT",
        "exclude_internal_types": "true"
    }
    
    session = get_session()

    u = f"{url}/policy/api/v1/search"
    res = session.get(u, params=SEARCH_DSL_QUERY)
    
    if res.ok:
        print(res)
        sgs = sorted(res.json()['results'], key=lambda k: k['id'])
        for sg in res.json()['results']:
            json_formatted_str = json.dumps(sg, indent=4)
            #print(json_formatted_str)
            print(f"{sg['id']}, ")
            
    
  
if __name__ == "__main__":
    #bulk()
    #get_revison_number()
    #put_group()
    search()
