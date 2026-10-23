// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'types.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$ChatEvent {

/// Dispositivo que enviou, conforme o certificado de remetente.
 DeviceAddress get from;/// Texto decifrado.
 Uint8List get body;
/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ChatEventCopyWith<ChatEvent> get copyWith => _$ChatEventCopyWithImpl<ChatEvent>(this as ChatEvent, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent&&(identical(other.from, from) || other.from == from)&&const DeepCollectionEquality().equals(other.body, body));
}


@override
int get hashCode => Object.hash(runtimeType,from,const DeepCollectionEquality().hash(body));

@override
String toString() {
  return 'ChatEvent(from: $from, body: $body)';
}


}

/// @nodoc
abstract mixin class $ChatEventCopyWith<$Res>  {
  factory $ChatEventCopyWith(ChatEvent value, $Res Function(ChatEvent) _then) = _$ChatEventCopyWithImpl;
@useResult
$Res call({
 DeviceAddress from, Uint8List body
});




}
/// @nodoc
class _$ChatEventCopyWithImpl<$Res>
    implements $ChatEventCopyWith<$Res> {
  _$ChatEventCopyWithImpl(this._self, this._then);

  final ChatEvent _self;
  final $Res Function(ChatEvent) _then;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? from = null,Object? body = null,}) {
  return _then(_self.copyWith(
from: null == from ? _self.from : from // ignore: cast_nullable_to_non_nullable
as DeviceAddress,body: null == body ? _self.body : body // ignore: cast_nullable_to_non_nullable
as Uint8List,
  ));
}

}


/// Adds pattern-matching-related methods to [ChatEvent].
extension ChatEventPatterns on ChatEvent {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( ChatEvent_MessageReceived value)?  messageReceived,required TResult orElse(),}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( ChatEvent_MessageReceived value)  messageReceived,}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived():
return messageReceived(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( ChatEvent_MessageReceived value)?  messageReceived,}){
final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( DeviceAddress from,  Uint8List body)?  messageReceived,required TResult orElse(),}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that.from,_that.body);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( DeviceAddress from,  Uint8List body)  messageReceived,}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived():
return messageReceived(_that.from,_that.body);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( DeviceAddress from,  Uint8List body)?  messageReceived,}) {final _that = this;
switch (_that) {
case ChatEvent_MessageReceived() when messageReceived != null:
return messageReceived(_that.from,_that.body);case _:
  return null;

}
}

}

/// @nodoc


class ChatEvent_MessageReceived extends ChatEvent {
  const ChatEvent_MessageReceived({required this.from, required this.body}): super._();
  

/// Dispositivo que enviou, conforme o certificado de remetente.
@override final  DeviceAddress from;
/// Texto decifrado.
@override final  Uint8List body;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ChatEvent_MessageReceivedCopyWith<ChatEvent_MessageReceived> get copyWith => _$ChatEvent_MessageReceivedCopyWithImpl<ChatEvent_MessageReceived>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ChatEvent_MessageReceived&&(identical(other.from, from) || other.from == from)&&const DeepCollectionEquality().equals(other.body, body));
}


@override
int get hashCode => Object.hash(runtimeType,from,const DeepCollectionEquality().hash(body));

@override
String toString() {
  return 'ChatEvent.messageReceived(from: $from, body: $body)';
}


}

/// @nodoc
abstract mixin class $ChatEvent_MessageReceivedCopyWith<$Res> implements $ChatEventCopyWith<$Res> {
  factory $ChatEvent_MessageReceivedCopyWith(ChatEvent_MessageReceived value, $Res Function(ChatEvent_MessageReceived) _then) = _$ChatEvent_MessageReceivedCopyWithImpl;
@override @useResult
$Res call({
 DeviceAddress from, Uint8List body
});




}
/// @nodoc
class _$ChatEvent_MessageReceivedCopyWithImpl<$Res>
    implements $ChatEvent_MessageReceivedCopyWith<$Res> {
  _$ChatEvent_MessageReceivedCopyWithImpl(this._self, this._then);

  final ChatEvent_MessageReceived _self;
  final $Res Function(ChatEvent_MessageReceived) _then;

/// Create a copy of ChatEvent
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? from = null,Object? body = null,}) {
  return _then(ChatEvent_MessageReceived(
from: null == from ? _self.from : from // ignore: cast_nullable_to_non_nullable
as DeviceAddress,body: null == body ? _self.body : body // ignore: cast_nullable_to_non_nullable
as Uint8List,
  ));
}


}

// dart format on
