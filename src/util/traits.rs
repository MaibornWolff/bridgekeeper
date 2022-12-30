use crate::util::types::ObjectReference;

pub trait ObjectStore<T, V> {
    fn add_object(&mut self, object: T) -> Option<ObjectReference>;
    fn remove_object(&mut self, object: T);
    fn get_objects(&self) -> V;
}