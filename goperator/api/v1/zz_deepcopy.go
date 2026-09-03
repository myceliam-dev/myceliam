package v1

import "k8s.io/apimachinery/pkg/runtime"

func deepCopyStringMapSlice(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		if v == nil {
			out[k] = nil
			continue
		}
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func (in *AwsAccessProfile) DeepCopyInto(out *AwsAccessProfile) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Accounts = deepCopyStringMapSlice(in.Accounts)
}

func (in *AwsAccessProfile) DeepCopy() *AwsAccessProfile {
	if in == nil {
		return nil
	}
	out := new(AwsAccessProfile)
	in.DeepCopyInto(out)
	return out
}

func (in *AwsAccessProfile) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *AwsAccessProfileList) DeepCopyInto(out *AwsAccessProfileList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]AwsAccessProfile, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *AwsAccessProfileList) DeepCopy() *AwsAccessProfileList {
	if in == nil {
		return nil
	}
	out := new(AwsAccessProfileList)
	in.DeepCopyInto(out)
	return out
}

func (in *AwsAccessProfileList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *GcpAccessProfile) DeepCopyInto(out *GcpAccessProfile) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Projects = deepCopyStringMapSlice(in.Projects)
}

func (in *GcpAccessProfile) DeepCopy() *GcpAccessProfile {
	if in == nil {
		return nil
	}
	out := new(GcpAccessProfile)
	in.DeepCopyInto(out)
	return out
}

func (in *GcpAccessProfile) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *GcpAccessProfileList) DeepCopyInto(out *GcpAccessProfileList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]GcpAccessProfile, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *GcpAccessProfileList) DeepCopy() *GcpAccessProfileList {
	if in == nil {
		return nil
	}
	out := new(GcpAccessProfileList)
	in.DeepCopyInto(out)
	return out
}

func (in *GcpAccessProfileList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *AutoidpAllowlist) DeepCopyInto(out *AutoidpAllowlist) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Namespaces != nil {
		out.Namespaces = make([]string, len(in.Namespaces))
		copy(out.Namespaces, in.Namespaces)
	}
}

func (in *AutoidpAllowlist) DeepCopy() *AutoidpAllowlist {
	if in == nil {
		return nil
	}
	out := new(AutoidpAllowlist)
	in.DeepCopyInto(out)
	return out
}

func (in *AutoidpAllowlist) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *AutoidpAllowlistList) DeepCopyInto(out *AutoidpAllowlistList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]AutoidpAllowlist, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *AutoidpAllowlistList) DeepCopy() *AutoidpAllowlistList {
	if in == nil {
		return nil
	}
	out := new(AutoidpAllowlistList)
	in.DeepCopyInto(out)
	return out
}

func (in *AutoidpAllowlistList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
