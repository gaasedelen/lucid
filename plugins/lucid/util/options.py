#
# Custom helper classes created for and specifically-tailored to Lucid.
#  by Fireboyd78 - revision date is 2024/01/28 [initial public release]
#
#
# TODO:
# - Documentation/explanation of everything
# - Thorough bug-testing would be nice ;)
#
#
class OptionSet:
    
    def __init__(self, default_options={}):
        options = {}
        attrs = {}
        if default_options:
            if not isinstance(default_options, dict):
                raise TypeError(default_options)
            for name, value in default_options.items():
                attrs[name] = self._make_attr(name, value, options, default_options)
        self._options = options
        self._default_options = default_options
        self._attrs = attrs
    
    def _make_attr(self, name, value, options={}, default_options={}):
        options[name] = value
        def _get_attr(self, name):
            return options[name] if name in options else default_options[name]
        return _get_attr
    
    def __getattr__(self, name: str):
        try:
            return object.__getattribute__(self, name)
        except Exception as e:
            attrs = self.__dict__.get('_attrs', None)
            if not attrs or name not in attrs:
                # option attribute not found, re-raise the exception normally
                raise e
            return attrs[name](self, name)

    def __setattr__(self, name: str, value):
        attrs = self.__dict__.get('_attrs', None)
        if attrs is None or name not in attrs:
            object.__setattr__(self, name, value)
            return
        self.set(name, value)
    
    def __contains__(self, name: str):
        return self.contains(name)

    def __delitem__(self, name: str):
        self.remove(name)
    
    def __getitem__(self, name: str):
        options = self._get_options_list(name)
        return options[name]
        
    def __setitem__(self, name: str, value):
        self.set(name, value)
    
    
    def _get_options_list(self, name: str, allow_defaults=True):
        options = self._options
        if name not in options:
            options = self._default_options if allow_defaults else None
            if options is None:
                raise KeyError(name)
        return options

    def _get_option_internal(self, name: str, allow_defaults=True):
        options = self._get_options_list(name, allow_defaults=allow_defaults)
        if name not in options:
            return (False, None)
        return (True, options[name])
    
    
    def clear(self):
        self._options = {}
    
    def changes(self):
        changes = []
        for name, value in self._default_options.items():
            present, old_value = self._get_option_internal(name, allow_defaults=False)
            if not present or old_value == value:
                continue
            changes.append((name, old_value, value))
        return changes

    def restore_defaults(self):
        changes = self.changes()
        for name, _, new_value in changes:
            # directly set the value like the constructor does
            self._options[name] = new_value
        return changes

    def contains(self, name: str, check_defaults=True):
        options = self._get_options_list(name, allow_defaults=check_defaults)
        if name not in options:
            return False
        return True
    
    def remove(self, name: str):
        options = self._options
        if name not in options:
            raise KeyError(name)
        del options[name]
    
    def pop(self, name: str):
        _, value = self._get_option_internal(name, allow_defaults=False)
        self.remove(name)
        return value
    
    def restore(self, name: str):
        default_options = self._default_options
        if default_options is None or name not in default_options:
            raise KeyError(name, default_options)
        self.set(name, default_options[name])
    
    def get(self, name: str, default_value=None):
        need_default = True if default_value is None else False
        present, value = self._get_option_internal(name, allow_defaults=need_default)
        if not present:
            if default_value is None:
                raise KeyError(name)
            value = default_value
        return value

    def set(self, name: str, value):
        self._options[name] = value
    
    def has_default(self, name: str):
        return name in self._default_options
    
    def get_default(self, name: str):
        default_value = self._default_options.get(name, self)
        if default_value == self:
            raise KeyError(name)
        return default_value


class OptionListener:
    __providers = []
    
    def __init_subclass__(cls, /, providers=[], **kwargs):
        cls.__providers = providers
    
    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj.notify_creation()
        return obj
    
    def __del__(self):
        self.notify_deletion()
    
    def notify_creation(self):
        for provider in self.__providers:
            provider.add_listener(self)
    
    def notify_deletion(self):
        for provider in self.__providers:
            provider.remove_listener(self)
    
    def notify_change(self, option_name, option_value, **kwargs):
        print(f"**** notify_change[{self.__class__.__name__}]: {option_name} = {option_value}")


class OptionProvider(OptionSet):
    
    def __init__(self, default_options={}):
        super().__init__(default_options)
        self._listeners = []
    
    
    def _notify_change(self, option_name, option_value, **kwargs):
        for listener in self._listeners:
            listener.notify_change(option_name, option_value, **kwargs)
    
    def add_listener(self, listener):
        if listener not in self._listeners:
            self._listeners.append(listener)
            return True
        return False

    def remove_listener(self, listener):
        if listener not in self._listeners:
            return False
        self._listeners.remove(listener)
        return True

    def clear(self):
        if self._listeners:
            for name, value in self._options:
                if not self.contains(name, check_defaults=False):
                    continue
                super().remove(name) # don't notify listeners
                self._notify_change(name, None, deleted=True, old_value=value)
        super().clear()
    
    def refresh(self):
        if not self._listeners:
            return
        for name, value in self._options:
            self._notify_change(name, value)
    
    def reset(self):
        self._listeners.clear()
        super().restore_defaults() # no need to notify listeners
    
    def restore_defaults(self):
        for name, old_value, new_value in self.changes():
            self._notify_change(name, new_value, reset=True, old_value=old_value)
    
    def set(self, name: str, value):
        present, old_value = self._get_option_internal(name, allow_defaults=False)
        if not present:
            # notify of new value    
            super().set(name, value)
            self._notify_change(name, value)
            return
        elif value != old_value:
            super().set(name, value)
            # notify of updated value
            self._notify_change(name, value, old_value=old_value)
    
    def pop(self, name: str):
        old_value = super().pop(name)
        self._notify_change(name, None, deleted=True, old_value=old_value)
        return old_value
    
    def remove(self, name: str):
        if self._listeners:
            self.pop(name)
            return
        super().remove(name)