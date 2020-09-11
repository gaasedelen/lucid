import os
import sys
import weakref

from types import ModuleType

# py3/py2 compat
try:
    from importlib import reload 
except:
    pass

#------------------------------------------------------------------------------
# Python Callback / Signals
#------------------------------------------------------------------------------

def register_callback(callback_list, callback):
    """
    Register a callable function to the given callback_list.

    Adapted from http://stackoverflow.com/a/21941670
    """

    # create a weakref callback to an object method
    try:
        callback_ref = weakref.ref(callback.__func__), weakref.ref(callback.__self__)

    # create a wweakref callback to a stand alone function
    except AttributeError:
        callback_ref = weakref.ref(callback), None

    # 'register' the callback
    callback_list.append(callback_ref)

def notify_callback(callback_list, *args):
    """
    Notify the given list of registered callbacks of an event.

    The given list (callback_list) is a list of weakref'd callables
    registered through the register_callback() function. To notify the
    callbacks of an event, this function will simply loop through the list
    and call them.

    This routine self-heals by removing dead callbacks for deleted objects as
    it encounters them.

    Adapted from http://stackoverflow.com/a/21941670
    """
    cleanup = []

    #
    # loop through all the registered callbacks in the given callback_list,
    # notifying active callbacks, and removing dead ones.
    #

    for callback_ref in callback_list:
        callback, obj_ref = callback_ref[0](), callback_ref[1]

        #
        # if the callback is an instance method, deference the instance
        # (an object) first to check that it is still alive
        #

        if obj_ref:
            obj = obj_ref()

            # if the object instance is gone, mark this callback for cleanup
            if obj is None:
                cleanup.append(callback_ref)
                continue

            # call the object instance callback
            try:
                callback(obj, *args)

            # assume a Qt cleanup/deletion occurred
            except RuntimeError as e:
                cleanup.append(callback_ref)
                continue

        # if the callback is a static method...
        else:

            # if the static method is deleted, mark this callback for cleanup
            if callback is None:
                cleanup.append(callback_ref)
                continue

            # call the static callback
            callback(*args)

    # remove the deleted callbacks
    for callback_ref in cleanup:
        callback_list.remove(callback_ref)

#------------------------------------------------------------------------------
# Module Reloading
#------------------------------------------------------------------------------

def reload_package(target_module):
    """
    Recursively reload a 'stateless' python module / package.
    """
    target_name = target_module.__name__
    visited_modules = {target_name: target_module}
    _recurseive_reload(target_module, target_name, visited_modules)

def _recurseive_reload(module, target_name, visited):
    ignore = ["__builtins__", "__cached__", "__doc__", "__file__", "__loader__", "__name__", "__package__", "__spec__", "__path__"]
    
    visited[module.__name__] = module

    for attribute_name in dir(module):

        # skip the stuff we don't care about
        if attribute_name in ignore:
            continue

        attribute_value = getattr(module, attribute_name)

        if type(attribute_value) == ModuleType:
            attribute_module_name = attribute_value.__name__
            attribute_module = attribute_value
            #print("Found module %s" % attribute_module_name)
        elif callable(attribute_value):
            attribute_module_name = attribute_value.__module__
            attribute_module = sys.modules[attribute_module_name]
            #print("Found callable...", attribute_name)
        elif isinstance(attribute_value, dict) or isinstance(attribute_value, list) or isinstance(attribute_value, int):
            #print("TODO: should probably try harder to reload this...", attribute_name, type(attribute_value))
            continue
        else:
            #print("UNKNOWN TYPE TO RELOAD", attribute_name, type(attribute_value))
            raise ValueError("OH NOO RELOADING IS HARD")

        if not target_name in attribute_module_name:
            #print(" - Not a module of interest...")
            continue

        if "__plugins__" in attribute_module_name:
            #print(" - Skipping IDA base plugin module...")
            continue

        if attribute_module_name in visited:
            continue

        #print("going down...")
        _recurseive_reload(attribute_module, target_name, visited)
    
    #print("Okay done with %s, reloading self!" % module.__name__)
    reload(module)