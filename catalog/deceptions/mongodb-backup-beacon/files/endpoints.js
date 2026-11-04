db.getSiblingDB('integrations').getCollection('endpoints').insertOne({
  name: 'sync-service',
  uri: 'mongodb://svc-sync:XS2ZCOqpzSswI0mHO5fd@Honeytoken-Domain:27017/integrations?authSource=admin'
});
